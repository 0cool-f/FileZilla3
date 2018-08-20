#include <filezilla.h>
#include "ratelimiter.h"

#include <libfilezilla/event_handler.hpp>

#include <assert.h>

static int const tickDelay = 250;

CRateLimiter::CRateLimiter(fz::event_loop& loop, COptionsBase& options)
	: event_handler(loop)
	, options_(options)
{
	RegisterOption(OPTION_SPEEDLIMIT_ENABLE);
	RegisterOption(OPTION_SPEEDLIMIT_INBOUND);
	RegisterOption(OPTION_SPEEDLIMIT_OUTBOUND);

	m_tokenDebt[0] = 0;
	m_tokenDebt[1] = 0;
}

CRateLimiter::~CRateLimiter()
{
	remove_handler();
}

int64_t CRateLimiter::GetLimit(rate_direction direction) const
{
	int64_t ret{};
	if (options_.GetOptionVal(OPTION_SPEEDLIMIT_ENABLE) != 0) {
		ret = static_cast<int64_t>(options_.GetOptionVal(OPTION_SPEEDLIMIT_INBOUND + direction)) * 1024;
	}

	return ret;
}

void CRateLimiter::AddObject(CRateLimiterObject* pObject)
{
	fz::scoped_lock lock(sync_);

	objects_.push_back(pObject);

	for (int i = 0; i < 2; ++i) {
		int64_t limit = GetLimit(static_cast<rate_direction>(i));
		if (limit > 0) {
			int64_t tokens = limit / (1000 / tickDelay);

			tokens /= objects_.size();
			if (m_tokenDebt[i] > 0) {
				if (tokens >= m_tokenDebt[i]) {
					tokens -= m_tokenDebt[i];
					m_tokenDebt[i] = 0;
				}
				else {
					tokens = 0;
					m_tokenDebt[i] -= tokens;
				}
			}

			pObject->m_bytesAvailable[i] = tokens;

			if (!m_timer) {
				m_timer = add_timer(fz::duration::from_milliseconds(tickDelay), false);
			}
		}
		else {
			pObject->m_bytesAvailable[i] = -1;
		}
	}
}

void CRateLimiter::RemoveObject(CRateLimiterObject* pObject)
{
	fz::scoped_lock lock(sync_);

	for (size_t i = 0; i < objects_.size(); ++i) {
		auto * const object = objects_[i];
		if (object == pObject) {
			for (int direction = 0; direction < 2; ++direction) {
				// If an object already used up some of its assigned tokens, add them to m_tokenDebt,
				// so that newly created objects get less initial tokens.
				// That ensures that rapidly adding and removing objects does not exceed the rate
				int64_t limit = GetLimit(static_cast<rate_direction>(direction));
				int64_t tokens = limit / (1000 / tickDelay);
				tokens /= objects_.size();
				if (object->m_bytesAvailable[direction] < tokens) {
					m_tokenDebt[direction] += tokens - object->m_bytesAvailable[direction];
				}
			}
			objects_[i] = objects_[objects_.size() - 1];
			objects_.pop_back();
			break;
		}
	}

	for (int direction = 0; direction < 2; ++direction) {
		for (size_t i = 0; i < wakeupList_[direction].size(); ++i) {
			auto * const object = wakeupList_[direction][i];
			if (object == pObject) {
				wakeupList_[direction][i] = wakeupList_[direction][wakeupList_[direction].size() - 1];
				wakeupList_[direction].pop_back();
				break;
			}
		}
	}
}

void CRateLimiter::OnTimer(fz::timer_id)
{
	fz::scoped_lock lock(sync_);

	int64_t const limits[2] = { GetLimit(inbound), GetLimit(outbound) };

	for (int i = 0; i < 2; ++i) {
		m_tokenDebt[i] = 0;

		if (objects_.empty()) {
			continue;
		}

		if (limits[i] == 0) {
			for (auto iter = objects_.begin(); iter != objects_.end(); ++iter) {
				(*iter)->m_bytesAvailable[i] = -1;
				if ((*iter)->m_waiting[i]) {
					wakeupList_[i].push_back(*iter);
				}
			}
			continue;
		}

		int64_t tokens = (limits[i] * tickDelay) / 1000;
		int64_t maxTokens = tokens * GetBucketSize();

		// Get amount of tokens for each object
		int64_t tokensPerObject = tokens / objects_.size();

		if (tokensPerObject == 0) {
			tokensPerObject = 1;
		}
		tokens = 0;

		// This list will hold all objects which didn't reach maxTokens
		std::vector<CRateLimiterObject*> unsaturatedObjects;

		for (auto * object : objects_) {
			if (object->m_bytesAvailable[i] == -1) {
				assert(!object->m_waiting[i]);
				object->m_bytesAvailable[i] = tokensPerObject;
				unsaturatedObjects.push_back(object);
			}
			else {
				object->m_bytesAvailable[i] += tokensPerObject;
				if (object->m_bytesAvailable[i] > maxTokens) {
					tokens += object->m_bytesAvailable[i] - maxTokens;
					object->m_bytesAvailable[i] = maxTokens;
				}
				else {
					unsaturatedObjects.push_back(object);
				}

				if (object->m_waiting[i]) {
					wakeupList_[i].push_back(object);
				}
			}
		}

		// If there are any left-over tokens (in case of objects with a rate below the limit)
		// assign to the unsaturated sources
		while (tokens != 0 && !unsaturatedObjects.empty()) {
			tokensPerObject = tokens / unsaturatedObjects.size();
			if (tokensPerObject == 0) {
				break;
			}
			tokens = 0;

			std::vector<CRateLimiterObject*> objects;
			objects.swap(unsaturatedObjects);

			for (auto * object : objects) {
				object->m_bytesAvailable[i] += tokensPerObject;
				if (object->m_bytesAvailable[i] > maxTokens) {
					tokens += object->m_bytesAvailable[i] - maxTokens;
					object->m_bytesAvailable[i] = maxTokens;
				}
				else {
					unsaturatedObjects.push_back(object);
				}
			}
		}
	}

	WakeupWaitingObjects(lock);

	if (objects_.empty() || (limits[inbound] == 0 && limits[outbound] == 0)) {
		if (m_timer) {
			stop_timer(m_timer);
			m_timer = 0;
		}
	}
}

void CRateLimiter::WakeupWaitingObjects(fz::scoped_lock & l)
{
	for (int i = 0; i < 2; ++i) {
		while (!wakeupList_[i].empty()) {
			CRateLimiterObject* pObject = wakeupList_[i].back();
			wakeupList_[i].pop_back();
			if (!pObject->m_waiting[i]) {
				continue;
			}

			assert(pObject->m_bytesAvailable[i] != 0);
			pObject->m_waiting[i] = false;

			l.unlock(); // Do not hold while executing callback
			pObject->OnRateAvailable((rate_direction)i);
			l.lock();
		}
	}
}

int CRateLimiter::GetBucketSize() const
{
	const int burst_tolerance = options_.GetOptionVal(OPTION_SPEEDLIMIT_BURSTTOLERANCE);

	int bucket_size = 1000 / tickDelay;
	switch (burst_tolerance)
	{
	case 1:
		bucket_size *= 2;
		break;
	case 2:
		bucket_size *= 5;
		break;
	default:
		break;
	}

	return bucket_size;
}

void CRateLimiter::operator()(fz::event_base const& ev)
{
	fz::dispatch<fz::timer_event, CRateLimitChangedEvent>(ev, this,
		&CRateLimiter::OnTimer,
		&CRateLimiter::OnRateChanged);
}

void CRateLimiter::OnRateChanged()
{
	fz::scoped_lock lock(sync_);
	if (GetLimit(inbound) > 0 || GetLimit(outbound) > 0) {
		if (!m_timer) {
			m_timer = add_timer(fz::duration::from_milliseconds(tickDelay), false);
		}
	}
}

void CRateLimiter::OnOptionsChanged(changed_options_t const&)
{
	send_event<CRateLimitChangedEvent>();
}

CRateLimiterObject::CRateLimiterObject()
{
	for (int i = 0; i < 2; ++i) {
		m_waiting[i] = false;
		m_bytesAvailable[i] = -1;
	}
}

void CRateLimiterObject::UpdateUsage(CRateLimiter::rate_direction direction, int usedBytes)
{
	assert(usedBytes <= m_bytesAvailable[direction]);
	if (usedBytes > m_bytesAvailable[direction]) {
		m_bytesAvailable[direction] = 0;
	}
	else {
		m_bytesAvailable[direction] -= usedBytes;
	}
}

void CRateLimiterObject::Wait(CRateLimiter::rate_direction direction)
{
	assert(m_bytesAvailable[direction] == 0);
	m_waiting[direction] = true;
}

bool CRateLimiterObject::IsWaiting(CRateLimiter::rate_direction direction) const
{
	return m_waiting[direction];
}
