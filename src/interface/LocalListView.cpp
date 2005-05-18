#include "FileZilla.h"
#include "LocalListView.h"
#include "state.h"
#include "QueueView.h"
#include "filezillaapp.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

BEGIN_EVENT_TABLE(CLocalListView, wxListCtrl)
	EVT_LIST_ITEM_ACTIVATED(wxID_ANY, CLocalListView::OnItemActivated)
	EVT_LIST_COL_CLICK(wxID_ANY, CLocalListView::OnColumnClicked)
	EVT_CONTEXT_MENU(CLocalListView::OnContextMenu)
	// Map both ID_UPLOAD and ID_ADDTOQUEUE to OnMenuUpload, code is identical
	EVT_MENU(XRCID("ID_UPLOAD"), CLocalListView::OnMenuUpload)
	EVT_MENU(XRCID("ID_ADDTOQUEUE"), CLocalListView::OnMenuUpload)
	EVT_MENU(XRCID("ID_MKDIR"), CLocalListView::OnMenuMkdir)
	EVT_MENU(XRCID("ID_DELETE"), CLocalListView::OnMenuDelete)
	EVT_MENU(XRCID("ID_RENAME"), CLocalListView::OnMenuRename)
	EVT_CHAR(CLocalListView::OnChar)
	EVT_LIST_BEGIN_LABEL_EDIT(wxID_ANY, CLocalListView::OnBeginLabelEdit)
	EVT_LIST_END_LABEL_EDIT(wxID_ANY, CLocalListView::OnEndLabelEdit)
END_EVENT_TABLE()

CLocalListView::CLocalListView(wxWindow* parent, wxWindowID id, CState *pState, CQueueView *pQueue)
	: wxListCtrl(parent, id, wxDefaultPosition, wxDefaultSize, wxLC_VIRTUAL | wxLC_REPORT | wxNO_BORDER | wxLC_EDIT_LABELS),
	CSystemImageList(16)
{
	m_pState = pState;
	m_pQueue = pQueue;

	InsertColumn(0, _("Filename"));
	InsertColumn(1, _("Filesize"));
	InsertColumn(2, _("Filetype"));
	InsertColumn(3, _("Last modified"), wxLIST_FORMAT_LEFT, 100);

	m_sortColumn = 0;
	m_sortDirection = 0;

	SetImageList(GetSystemImageList(), wxIMAGE_LIST_SMALL);

#ifdef __WXMSW__
	// Initialize imagelist for list header
	m_pHeaderImageList = new wxImageListEx(8, 8, true, 3);

	wxBitmap bmp;
	
	bmp.LoadFile(wxGetApp().GetResourceDir() + _T("empty.xpm"), wxBITMAP_TYPE_XPM);
	m_pHeaderImageList->Add(bmp);
	bmp.LoadFile(wxGetApp().GetResourceDir() + _T("up.xpm"), wxBITMAP_TYPE_XPM);
	m_pHeaderImageList->Add(bmp);
	bmp.LoadFile(wxGetApp().GetResourceDir() + _T("down.xpm"), wxBITMAP_TYPE_XPM);
	m_pHeaderImageList->Add(bmp);

	HWND hWnd = (HWND)GetHandle();
	if (!hWnd)
	{
		delete m_pHeaderImageList;
		m_pHeaderImageList = 0;
		return;
	}

	HWND header = (HWND)SendMessage(hWnd, LVM_GETHEADER, 0, 0);
	if (!header)
	{
		delete m_pHeaderImageList;
		m_pHeaderImageList = 0;
		return;
	}

	TCHAR buffer[1000] = {0};
	HDITEM item;
	item.mask = HDI_TEXT;
	item.pszText = buffer;
	item.cchTextMax = 999;
	SendMessage(header, HDM_GETITEM, 0, (LPARAM)&item);

	SendMessage(header, HDM_SETIMAGELIST, 0, (LPARAM)m_pHeaderImageList->GetHandle());
#endif
}

CLocalListView::~CLocalListView()
{
#ifdef __WXMSW__
	delete m_pHeaderImageList;
#endif
}

void CLocalListView::DisplayDir(wxString dirname)
{
	m_dir = dirname;

	m_fileData.clear();
	m_indexMapping.clear();

	t_fileData data;
	data.dir = true;
	data.icon = -2;
	data.name = _T("..");
	data.size = -1;
	data.hasTime = 0;
	m_fileData.push_back(data);
	m_indexMapping.push_back(0);

#ifdef __WXMSW__
	if (dirname == _T("\\"))
	{
		DisplayDrives();
	}
	else
#endif
	{
		wxDir dir(dirname);
		wxString file;
		bool found = dir.GetFirst(&file);
		int num = 1;
		while (found)
		{
			wxFileName fn(dirname + file);
			t_fileData data;
			data.dir = fn.DirExists();
			data.icon = -2;
			data.name = fn.GetFullName();
	
			wxStructStat buf;
			int result;
			result = wxStat(fn.GetFullPath(), &buf);

			if (!result)
			{
				data.hasTime = true;
				data.lastModified = wxDateTime(buf.st_mtime);
			}
			else              
				data.hasTime = false;

			if (data.dir)
				data.size = -1;
			else
				data.size = result ? -1 : buf.st_size;

			m_fileData.push_back(data);
			m_indexMapping.push_back(num);
			num++;

			found = dir.GetNext(&file);
		}
		SetItemCount(num);
	}

	SortList();
}

// Declared const due to design error in wxWidgets.
// Won't be fixed since a fix would break backwards compatibility
// Both functions use a const_cast<CLocalListView *>(this) and modify
// the instance.
wxString CLocalListView::OnGetItemText(long item, long column) const
{
	CLocalListView *pThis = const_cast<CLocalListView *>(this);
	t_fileData *data = pThis->GetData(item);
	if (!data)
		return _T("");

	if (!column)
		return data->name;
	else if (column == 1)
	{
		if (data->size < 0)
			return _T("");
		else
			return wxLongLong(data->size).ToString();
	}
	else if (column == 2 && item)
	{
		if (data->fileType == _T(""))
			data->fileType = pThis->GetType(data->name, data->dir);

		return data->fileType;
	}
	else if (column == 3)
	{
		if (!data->hasTime)
			return _T("");

		return data->lastModified.Format(_T("%c"));
	}
	return _T("");
}

// See comment to OnGetItemText
int CLocalListView::OnGetItemImage(long item) const
{
	CLocalListView *pThis = const_cast<CLocalListView *>(this);
	t_fileData *data = pThis->GetData(item);
	if (!data)
		return -1;
	int &icon = data->icon;

	if (icon == -2)
	{
		wxString path = _T("");
		if (data->name != _T(".."))
		{
#ifdef __WXMSW__
			if (m_dir == _T("\\"))
				path = data->name + _T("\\");
			else
#endif
				path = m_dir + data->name;
		}

		icon = pThis->GetIconIndex(data->dir ? dir : file, path);
	}
	return icon;
}

void CLocalListView::OnItemActivated(wxListEvent &event)
{
	int count = 0;
	bool back = false;

	int item = -1;
	while (true)
	{
		item = GetNextItem(item, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
		if (item == -1)
			break;

		count++;

		if (!item)
			back = true;
	}
	if (count > 1)
	{
		if (back)
		{
			wxBell();
			return;
		}

		wxCommandEvent cmdEvent;
		OnMenuUpload(cmdEvent);
		return;
	}

	item = event.GetIndex();
	
	t_fileData *data = GetData(item);
	if (!data)
		return;
	
	if (!item)
		m_pState->SetLocalDir(data->name);
	else
	{
		if (data->dir)
			m_pState->SetLocalDir(data->name);
		else
		{
			const CServer* pServer = m_pState->GetServer();
			if (!pServer)
			{
				wxBell();
				return;
			}

			CServerPath path = m_pState->GetRemotePath();
			if (path.IsEmpty())
			{
				wxBell();
				return;
			}

			wxFileName fn(m_dir, data->name);

			m_pQueue->QueueFile(false, false, fn.GetFullPath(), data->name, path, *pServer, data->size);
		}
	}
}

#ifdef __WXMSW__
void CLocalListView::DisplayDrives()
{
	TCHAR  szDrives[128];
	LPTSTR pDrive;

	GetLogicalDriveStrings( sizeof(szDrives), szDrives );
	
	pDrive = szDrives;
	int count = 1;
	while(*pDrive)
	{
		wxString path = pDrive;
		t_fileData data;
		if (path.Right(1) == _T("\\"))
			path.Truncate(path.Length() - 1);

		data.name = path;
		data.dir = true;
		data.icon = -2;
		data.size = -1;
		data.hasTime = false;
		
		m_fileData.push_back(data);
		m_indexMapping.push_back(count);
#ifdef _tcslen
		pDrive += _tcslen(pDrive) + 1;
#else
		pDrive += strlen(pDrive) + 1;
#endif
		count++;
	}
	SetItemCount(count);
}
#endif

wxString CLocalListView::GetType(wxString name, bool dir)
{
	wxString type;
#ifdef __WXMSW__
	wxString ext = wxFileName(name).GetExt();
	ext.MakeLower();
	std::map<wxString, wxString>::iterator typeIter = m_fileTypeMap.find(ext);
	if (typeIter != m_fileTypeMap.end())
		type = typeIter->second;
	else
	{
		wxString path;
#ifdef __WXMSW__
		if (m_dir == _T("\\"))
			path = name + _T("\\");
		else
#endif
			path = m_dir + name;
		SHFILEINFO shFinfo;		
		memset(&shFinfo,0,sizeof(SHFILEINFO));
		if (SHGetFileInfo(path,
			dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL,
			&shFinfo,
			sizeof(shFinfo),
			SHGFI_TYPENAME))
		{
			type = shFinfo.szTypeName;
			if (type == _T(""))
			{
				type = ext;
				type.MakeUpper();
				if (!type.IsEmpty())
				{
					type += _T("-");
					type += _("file");
				}
				else
					type = _("File");
			}
			else
			{
				if (!dir && ext != _T(""))
					m_fileTypeMap[ext.MakeLower()] = type;
			}
		}
		else
		{
			type = ext;
			type.MakeUpper();
			if (!type.IsEmpty())
			{
				type += _T("-");
				type += _("file");
			}
			else
				type = _("File");
		}
	}
#else
	type = dir ? _("Folder") : _("File");
#endif
	return type;
}

CLocalListView::t_fileData* CLocalListView::GetData(unsigned int item)
{
	if (!IsItemValid(item))
		return 0;

	return &m_fileData[m_indexMapping[item]];
}

bool CLocalListView::IsItemValid(unsigned int item) const
{
	if (item > m_indexMapping.size())
		return false;

	unsigned int index = m_indexMapping[item];
	if (index > m_fileData.size())
		return false;

	return true;
}

void CLocalListView::SortList(int column /*=-1*/, int direction /*=-1*/)
{
	if (column != -1)
	{
#ifdef __WXMSW__
		if (column != m_sortColumn && m_pHeaderImageList)
		{
			HWND hWnd = (HWND)GetHandle();
			HWND header = (HWND)SendMessage(hWnd, LVM_GETHEADER, 0, 0);

			wxChar buffer[100];
			HDITEM item;
			item.mask = HDI_TEXT | HDI_FORMAT;
			item.pszText = buffer;
			item.cchTextMax = 99;
			SendMessage(header, HDM_GETITEM, m_sortColumn, (LPARAM)&item);
			item.mask |= HDI_IMAGE;
			item.fmt |= HDF_IMAGE | HDF_BITMAP_ON_RIGHT;
			item.iImage = 0;
			SendMessage(header, HDM_SETITEM, m_sortColumn, (LPARAM)&item);
		}
#endif
		m_sortColumn = column;
	}
	if (direction != -1)
		m_sortDirection = direction;

#ifdef __WXMSW__
	if (m_pHeaderImageList)
	{
		HWND hWnd = (HWND)GetHandle();
		HWND header = (HWND)SendMessage(hWnd, LVM_GETHEADER, 0, 0);

		wxChar buffer[100];
		HDITEM item;
		item.mask = HDI_TEXT | HDI_FORMAT;
		item.pszText = buffer;
		item.cchTextMax = 99;
		SendMessage(header, HDM_GETITEM, m_sortColumn, (LPARAM)&item);
		item.mask |= HDI_IMAGE;
		item.fmt |= HDF_IMAGE | HDF_BITMAP_ON_RIGHT;
		item.iImage = m_sortDirection ? 2 : 1;
		SendMessage(header, HDM_SETITEM, m_sortColumn, (LPARAM)&item);
	}
#endif

	if (GetItemCount() < 3)
		return;

	if (!m_sortColumn)
		QSortList(m_sortDirection, 1, m_fileData.size() - 1, CmpName);
	else if (m_sortColumn == 1)
		QSortList(m_sortDirection, 1, m_fileData.size() - 1, CmpSize);
	else if (m_sortColumn == 2)
		QSortList(m_sortDirection, 1, m_fileData.size() - 1, CmpType);
	RefreshItems(1, m_fileData.size() - 1);
}

void CLocalListView::OnColumnClicked(wxListEvent &event)
{
	int col = event.GetColumn();
	if (col == -1)
		return;

	int dir;
	if (col == m_sortColumn)
		dir = m_sortDirection ? 0 : 1;
	else
		dir = m_sortDirection;
	
	SortList(col, dir);
}

void CLocalListView::QSortList(const unsigned int dir, unsigned int anf, unsigned int ende, int (*comp)(CLocalListView *pList, unsigned int index, t_fileData &refData))
{
	unsigned int l = anf;
	unsigned int r = ende;
	const unsigned int ref = (l + r) / 2;
	t_fileData &refData = m_fileData[m_indexMapping[ref]];
	do
    {
		if (!dir)
		{
			while ((comp(this, l, refData) < 0) && (l<ende)) l++;
			while ((comp(this, r, refData) > 0) && (r>anf)) r--;
		}
		else
		{
			while ((comp(this, l, refData) > 0) && (l<ende)) l++;
			while ((comp(this, r, refData) < 0) && (r>anf)) r--;
		}
		if (l<=r)
		{
			unsigned int tmp = m_indexMapping[l];
			m_indexMapping[l] = m_indexMapping[r];
			m_indexMapping[r] = tmp;
			l++;
			r--;
		}
    } 
	while (l<=r);

	if (anf<r) QSortList(dir, anf, r, comp);
	if (l<ende) QSortList(dir, l, ende, comp);
}

int CLocalListView::CmpName(CLocalListView *pList, unsigned int index, t_fileData &refData)
{
	const t_fileData &data = pList->m_fileData[pList->m_indexMapping[index]];

	if (data.dir)
	{
		if (!refData.dir)
			return -1;
	}
	else if (refData.dir)
		return 1;

	return data.name.CmpNoCase(refData.name);
}

int CLocalListView::CmpType(CLocalListView *pList, unsigned int index, t_fileData &refData)
{
	t_fileData &data = pList->m_fileData[pList->m_indexMapping[index]];

	if (refData.fileType == _T(""))
		refData.fileType = pList->GetType(refData.name, refData.dir);
	if (data.fileType == _T(""))
		data.fileType = pList->GetType(data.name, data.dir);

	if (data.dir)
	{
		if (!refData.dir)
			return -1;
	}
	else if (refData.dir)
		return 1;

	int res = data.fileType.CmpNoCase(refData.fileType);
	if (res)
		return res;
	
	return data.name.CmpNoCase(refData.name);
}

int CLocalListView::CmpSize(CLocalListView *pList, unsigned int index, t_fileData &refData)
{
	t_fileData &data = pList->m_fileData[pList->m_indexMapping[index]];

	if (data.dir)
	{
		if (!refData.dir)
			return -1;
		else
			return data.name.CmpNoCase(refData.name);
	}
	else if (refData.dir)
		return 1;

	if (data.size == -1)
	{
		if (refData.size == -1)
			return 0;
		else
			return -1;
	}
	else if (refData.size == -1)
		return 1;

	wxLongLong res = data.size - refData.size;
	if (res > 0)
		return 1;
	else if (res < 0)
		return -1;

	return data.name.CmpNoCase(refData.name);

}

void CLocalListView::OnContextMenu(wxContextMenuEvent& event)
{
	wxMenu* pMenu = wxXmlResource::Get()->LoadMenu(_T("ID_MENU_LOCALFILELIST"));
	if (!pMenu)
		return;

	if (GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED) == -1)
	{
		pMenu->Enable(XRCID("ID_UPLOAD"), false);
		pMenu->Enable(XRCID("ID_ADDTOQUEUE"), false);
		pMenu->Enable(XRCID("ID_DELETE"), false);
		pMenu->Enable(XRCID("ID_RENAME"), false);
	}

	PopupMenu(pMenu);
	delete pMenu;
}

void CLocalListView::OnMenuUpload(wxCommandEvent& event)
{
	long item = -1;
	while (true)
	{
		item = GetNextItem(item, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
		if (item == -1)
			break;

		if (!item)
			return;
	}

	item = -1;
	while (true)
	{
		item = GetNextItem(item, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
		if (item == -1)
			break;

		t_fileData *data = GetData(item);
		if (!data)
			return;
	
		if (!item)
			m_pState->SetLocalDir(data->name);
		else
		{
			const CServer* pServer = m_pState->GetServer();
			if (!pServer)
			{
				wxBell();
				return;
			}

			CServerPath path = m_pState->GetRemotePath();
			if (path.IsEmpty())
			{
				wxBell();
				return;
			}

			if (data->dir)
			{
				path.ChangePath(data->name);

				wxFileName fn(m_dir, _T(""));
				fn.AppendDir(data->name);
				m_pQueue->QueueFolder(event.GetId() == XRCID("ID_ADDTOQUEUE"), false, fn.GetPath(), path, *pServer);
			}
			else
			{
				wxFileName fn(m_dir, data->name);

				m_pQueue->QueueFile(event.GetId() == XRCID("ID_ADDTOQUEUE"), false, fn.GetFullPath(), data->name, path, *pServer, data->size);
			}
		}
	}
}

void CLocalListView::OnMenuMkdir(wxCommandEvent& event)
{
}

void CLocalListView::OnMenuDelete(wxCommandEvent& event)
{
	// Under Windows use SHFileOperation delete files and directories.
	// Under other systems, we have to recurse into subdirectories manually
	// to delete all contents.

#ifdef __WXMSW__
	// SHFileOperation accepts a list of null-terminated strings. Go through all
	// items to get the required buffer length

	wxString dir = m_dir;
	if (dir.Right(1) != _T("\\") && dir.Right(1) != _T("/"))
		dir += _T("\\");
	int dirLen = dir.Length();

	int len = 1; // String list terminated by empty string

	long item = -1;
	while (true)
	{
		item = GetNextItem(item, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
		if (item == -1)
			break;

		if (!item)
			continue;
        
		t_fileData *data = GetData(item);
		if (!data)
			continue;
	
		len += dirLen + data->name.Length() + 1;
	}

	// Allocate memory
	wxChar* pBuffer = new wxChar[len];
	wxChar* p = pBuffer;

	// Loop through all selected items again and fill buffer
	item = -1;
	while (true)
	{
		item = GetNextItem(item, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
		if (item == -1)
			break;

		if (!item)
			continue;
        
		t_fileData *data = GetData(item);
		if (!data)
			continue;

		_tcscpy(p, dir);
		p += dirLen;
		_tcscpy(p, data->name);
		p += data->name.Length() + 1;
	}
	*p = 0;

	// Now we can delete the files in the buffer
	SHFILEOPSTRUCT op;
	memset(&op, 0, sizeof(op));
	op.hwnd = (HWND)GetHWND();
	op.wFunc = FO_DELETE;
	op.pFrom = pBuffer;

	// Move to trash if shift is not pressed, else delete
	op.fFlags = wxGetKeyState(WXK_SHIFT) ? 0 : FOF_ALLOWUNDO;

	SHFileOperation(&op);
	delete [] pBuffer;
#else
	if (wxMessageBox(_("Really delete all selected files and/or directories?"), _("Confirmation needed"), wxICON_QUESTION | wxYES_NO, this) != wxYES)
		return;

	// Remember the directories to delete and the directories to visit
	std::list<wxString> dirsToDelete;
	std::list<wxString> dirsToVisit;

	wxString dir = m_dir;
	if (dir.Right(1) != _T("\\") && dir.Right(1) != _T("/"))
		dir += _T("/");

	// First process selected items
	long item = -1;
	while (true)
	{
		item = GetNextItem(item, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
		if (item == -1)
			break;

		if (!item)
			continue;
        
		t_fileData *data = GetData(item);
		if (!data)
			continue;
	
		if (data->dir)
		{
			wxString subDir = dir + data->name + _T("/");
			dirsToVisit.push_back(subDir);
			dirsToDelete.push_front(subDir);
		}
		else
			wxRemoveFile(dir + data->name);
	}

	// Process any subdirs which still have to be visited
	while (!dirsToVisit.empty())
	{
		wxString filename = dirsToVisit.front();
		dirsToVisit.pop_front();
		wxDir dir;
		if (!dir.Open(filename))
			continue;

		wxString file;
		for (bool found = dir.GetFirst(&file); found; found = dir.GetNext(&file))
		{
			if (wxFileName::DirExists(filename + file))
			{
				wxString subDir = filename + file + _T("/");
				dirsToVisit.push_back(subDir);
				dirsToDelete.push_front(subDir);
			}
			else
				wxRemoveFile(filename + file);
		}
	}
	
	// Delete the now empty directories
	for (std::list<wxString>::const_iterator iter = dirsToDelete.begin(); iter != dirsToDelete.end(); iter++)
		wxRmdir(*iter);

#endif
	m_pState->SetLocalDir(m_dir);
}

void CLocalListView::OnMenuRename(wxCommandEvent& event)
{
	int item = GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
	if (item <= 0)
	{
		wxBell();
		return;
	}

	if (GetNextItem(item, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED) != -1)
	{
		wxBell();
		return;
	}

	EditLabel(item);
}

void CLocalListView::OnChar(wxKeyEvent& event)
{
	int code = event.GetKeyCode();
	if (code == WXK_DELETE)
	{
		if (GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED) == -1)
		{
			wxBell();
			return;
		}

		wxCommandEvent tmp;
		OnMenuDelete(tmp);
	}
	else if (code == WXK_F2)
	{
		wxCommandEvent tmp;
		OnMenuRename(tmp);
	}
	else if (code > 32 && code < 300 && !event.HasModifiers())
	{
		// Keyboard navigation within items
		wxDateTime now = wxDateTime::UNow();
		if (m_lastKeyPress.IsValid())
		{
			wxTimeSpan span = now - m_lastKeyPress;
			if (span.GetSeconds() >= 1)
				m_prefix = _T("");
		}
		m_lastKeyPress = now;

		wxChar tmp[2];
#if wxUSE_UNICODE
		tmp[0] = event.GetUnicodeKey();
#else
		tmp[0] = code;
#endif
		tmp[1] = 0;
		wxString newPrefix = m_prefix + tmp;
		
		bool beep = false;
		int item = GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
		if (item != -1)
		{
			wxString text;
			if (!item)
				text = _T("..");
			else
				text = GetData(item)->name;
			if (text.Length() >= m_prefix.Length() && !m_prefix.CmpNoCase(text.Left(m_prefix.Length())))
				beep = true;
		}
		else if (m_prefix == _T(""))
			beep = true;

		int start = item;
		if (start < 0)
			start = 0;

		int newPos = FindItemWithPrefix(newPrefix, (item >= 0) ? item : 0);

		if (newPos == -1 && m_prefix == tmp && item != -1 && beep)
		{
			// Search the next item that starts with the same letter
			newPrefix = m_prefix;
			newPos = FindItemWithPrefix(newPrefix, item + 1);
		}
	
		m_prefix = newPrefix;
		if (newPos == -1)
		{
			if (beep)
				wxBell();
			return;
		}

		item = GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
		while (item != -1)
		{
			SetItemState(item, 0, wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED);
			item = GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
		}
		SetItemState(newPos, wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED, wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED);
		EnsureVisible(newPos);
	}
	else
		event.Skip();
}

int CLocalListView::FindItemWithPrefix(const wxString& prefix, int start)
{
	for (int i = start; i < (GetItemCount() + start); i++)
	{
		int item = i % GetItemCount();
		wxString fn;
		if (!item)
		{
			fn = _T("..");
			fn = fn.Left(prefix.Length());
		}
		else
		{
			t_fileData* data = GetData(item);
			if (!data)
				continue;
			fn = data->name.Left(prefix.Length());
		}
		if (!fn.CmpNoCase(prefix))
			return i % GetItemCount();
	}
	return -1;
}

void CLocalListView::OnBeginLabelEdit(wxListEvent& event)
{
	if (event.GetIndex() == 0)
	{
		event.Veto();
		return;
	}
}

void CLocalListView::OnEndLabelEdit(wxListEvent& event)
{
	if (event.GetLabel() == _T(""))
		return;

	wxString newname = event.GetLabel();
#ifdef __WXMSW__
	newname = newname.Left(255);

	if ((newname.Find('/') != -1) || 
		(newname.Find('\\') != -1) ||
		(newname.Find(':') != -1) ||
		(newname.Find('*') != -1) ||
		(newname.Find('?') != -1) || 
		(newname.Find('"') != -1) ||
		(newname.Find('<') != -1) ||
		(newname.Find('>') != -1) ||
		(newname.Find('|') != -1))
	{
		wxMessageBox(_("Filenames may not contain any of the following characters: / \\ : * ? \" < > |"), _("Invalid filename"), wxICON_EXCLAMATION);
		event.Veto();
		return;
	}
	
	SHFILEOPSTRUCT op;
	memset(&op, 0, sizeof(op));

	wxString dir = m_dir;
	if (dir.Right(1) != _T("\\") && dir.Right(1) != _T("/"))
		dir += _T("\\");
	wxString from = dir + m_fileData[m_indexMapping[event.GetItem()]].name + _T(" ");
	from.SetChar(from.Length() - 1, '\0');
	op.pFrom = from;
	wxString to = dir + newname + _T(" ");
	to.SetChar(to.Length()-1, '\0');
	op.pTo = to;
	op.hwnd = (HWND)GetHandle();
	op.wFunc = FO_RENAME;
	op.fFlags = FOF_ALLOWUNDO;
	if (SHFileOperation(&op))
		event.Veto();
	else
	{
		m_fileData[m_indexMapping[event.GetItem()]].name = newname;
		return;
	}
#else
	if ((newname.Find('/') != -1) || 
		(newname.Find('*') != -1) ||
		(newname.Find('?') != -1) || 
		(newname.Find('<') != -1) ||
		(newname.Find('>') != -1) ||
		(newname.Find('|') != -1))
	{
		wxMessageBox(_("Filenames may not contain any of the following characters: / * ? < > |"), _("Invalid filename"), wxICON_EXCLAMATION);
		event.Veto();
		return;
	}

	wxString dir = m_dir;
	if (dir.Right(1) != _T("\\") && dir.Right(1) != _T("/"))
		dir += _T("\\");
	if (wxRenameFile(dir + m_fileData[m_indexMapping[event.GetItem()]].name, dir + newname))
		m_fileData[m_indexMapping[event.GetItem()]].name = newname;
	else
		event.Veto();
#endif
}

