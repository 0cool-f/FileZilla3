#include <filezilla.h>
#include "option_change_event_handler.h"

#include <algorithm>

#include <libfilezilla/util.hpp>

std::vector<COptionChangeEventHandler*> COptionChangeEventHandler::m_handlers;
std::size_t COptionChangeEventHandler::notify_index_{};
fz::mutex COptionChangeEventHandler::m_{false};
COptionChangeEventHandler* COptionChangeEventHandler::active_handler_{};
fz::thread::id COptionChangeEventHandler::thread_id_;

COptionChangeEventHandler::~COptionChangeEventHandler()
{
	UnregisterAllOptions();
}

void COptionChangeEventHandler::UnregisterAllOptions()
{
	fz::scoped_lock l(m_);
	if (m_handled_options.any()) {
		auto it = std::find(m_handlers.begin(), m_handlers.end(), this);
		if (it != m_handlers.end()) {
			m_handlers.erase(it);
		}
	}

	if (active_handler_ == this) {
		if (fz::thread::own_id() != thread_id_) {
			while (active_handler_ == this) {
				l.unlock();
				fz::sleep(fz::duration::from_milliseconds(1));
				l.lock();
			}
		}
	}
}

void COptionChangeEventHandler::RegisterOption(int option)
{
	if (option < 0) {
		return;
	}

	fz::scoped_lock l(m_);
	if (m_handled_options.none()) {
		m_handlers.push_back(this);
	}
	m_handled_options.set(option);
}

void COptionChangeEventHandler::UnregisterOption(int option)
{
	fz::scoped_lock l(m_);
	m_handled_options.set(option, false);
	if (m_handled_options.none()) {
		auto it = std::find(m_handlers.begin(), m_handlers.end(), this);
		if (it != m_handlers.end()) {
			m_handlers.erase(it);

			// If this had been called in the context of DoNotify, make sure all handlers get called
			if (static_cast<std::size_t>(std::distance(m_handlers.begin(), it)) <= notify_index_) {
				--notify_index_;
			}
		}
	}
}

void COptionChangeEventHandler::UnregisterAllHandlers()
{
	fz::scoped_lock l(m_);
	for (auto & handler : m_handlers) {
		handler->m_handled_options.reset();
	}
	m_handlers.clear();
}

void COptionChangeEventHandler::DoNotify(changed_options_t const& options)
{
	fz::scoped_lock l(m_);

	assert(!active_handler_);

	// Going over notify_index_ which may be changed by UnregisterOption
	// Bit ugly but otherwise has reentrancy issues.
	for (notify_index_ = 0; notify_index_ < m_handlers.size(); ++notify_index_) {
		auto & handler = m_handlers[notify_index_];
		auto hoptions = options & handler->m_handled_options;
		if (hoptions.any()) {
			active_handler_ = handler;
			thread_id_ = fz::thread::own_id();

			l.unlock();
			handler->OnOptionsChanged(hoptions);
			l.lock();

			active_handler_ = nullptr;
		}
	}
}
