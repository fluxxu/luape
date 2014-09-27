#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <exception>
#include <algorithm>
#include <Windows.h>

class PEImage {
public:
	PEImage() : file_(NULL), map_(NULL), size_(0), data_(nullptr), image_base_(0) {}
	~PEImage() {
		Unload();
	}

	bool IsLoaded() {
		return data_ != nullptr;
	}

	void Unload() {
		if (data_) {
			CloseHandle(map_);
			CloseHandle(file_);
			map_ = NULL;
			file_ = NULL;
			data_ = nullptr;
			image_base_ = 0;
			sections_.clear();
		}
	}

	void Load(std::string path) {
		Unload();

		if (path.empty()) {
			throw std::exception("File path is empty");
		}

		char err_msg[100];
		HANDLE file = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (file == INVALID_HANDLE_VALUE) {
			sprintf_s(err_msg, "CreateFileA error: %d", GetLastError());
			throw std::exception(err_msg);
		}

		LARGE_INTEGER file_size = { 0 };
		GetFileSizeEx(file, &file_size);
		if (file_size.QuadPart > 1024 * 1024 * 1024) {
			CloseHandle(file);
			throw std::exception("Image is too large");
		}

		if (file_size.LowPart <= sizeof(IMAGE_DOS_HEADER)) {
			CloseHandle(file);
			throw std::exception("Image is not a PE file");
		}

		HANDLE map = CreateFileMapping(file, NULL, PAGE_READONLY, 0, 0, NULL);
		if (map == NULL) {
			CloseHandle(file);
			sprintf_s(err_msg, "CreateFileMapping error: %d", GetLastError());
			throw std::exception(err_msg);
		}

		auto close_and_throw = [&](const char *what) {
			CloseHandle(map);
			CloseHandle(file);
			file_ = 0;
			map_ = 0;
			data_ = nullptr;
			size_ = 0;
			image_base_ = 0;
			sections_.clear();
			throw std::exception(what);
		};

		data_ = reinterpret_cast<uint8_t *>(MapViewOfFile(map, FILE_MAP_READ, 0, 0, file_size.LowPart));
		if (data_ == NULL) {
			sprintf_s(err_msg, "MapViewOfFile error: %d", GetLastError());
			close_and_throw(err_msg);
		}

		if (memcmp(data_, "MZ", 2) != 0) {
			close_and_throw("Image is not a PE file");
		}

		auto out_of_range = [&](const char *what) {	
			sprintf_s(err_msg, "Find invalid offset: %s", what);
			close_and_throw(err_msg);
		};

		size_ = file_size.LowPart;
		IMAGE_DOS_HEADER *dos_header = reinterpret_cast<IMAGE_DOS_HEADER *>(data_);
		
		if (dos_header->e_lfanew < 0 || static_cast<size_t>(dos_header->e_lfanew) > size_ - sizeof(IMAGE_NT_HEADERS)) {
			out_of_range("e_lfanew");
		}

		IMAGE_NT_HEADERS *nt_headers = reinterpret_cast<IMAGE_NT_HEADERS *>(data_ + dos_header->e_lfanew);
		int section_count = nt_headers->FileHeader.NumberOfSections;
		image_base_ = nt_headers->OptionalHeader.ImageBase;

		int image_section_header_offset = dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS);
		if (image_section_header_offset + (section_count * sizeof(IMAGE_SECTION_HEADER)) > size_) {
			out_of_range("e_lfanew + sizeof(IMAGE_NT_HEADERS)");
		}

		IMAGE_SECTION_HEADER *sections = reinterpret_cast<IMAGE_SECTION_HEADER *>(data_ + image_section_header_offset);
		sections_.resize(section_count);

		for (int i = 0; i < section_count; ++i) {
			auto section = sections_[i] = sections + i;
			//printf("%s:0x%X-0x%X\n", section->Name, section->VirtualAddress, section->VirtualAddress + section->SizeOfRawData);
		}

		file_ = file;
		map_ = map;

		const char *filename = path.c_str();
		char version[32];
		auto rv = GetFileVersionInfoSizeA(filename, NULL);
		if (rv) {
			char *buffer = (char *)malloc(rv + 1);
			if (GetFileVersionInfoA(filename, NULL, rv, buffer)) {
				VS_FIXEDFILEINFO *pFixedInfo;	unsigned int infoLength;
				if (VerQueryValueA(buffer, "\\", reinterpret_cast<LPVOID *>(&pFixedInfo), &infoLength)){
					sprintf_s(version, "%u.%u.%u.%u",
						pFixedInfo->dwFileVersionMS >> 0x10,
						pFixedInfo->dwFileVersionMS & 0xFFFF,
						pFixedInfo->dwFileVersionLS >> 0x10,
						pFixedInfo->dwFileVersionLS & 0xFFFF);
				}
			}
			free(buffer);
			version_ = version;
		}
	}

	uint8_t * FindPointerByRVA(uint32_t rva) {
		if (!IsLoaded() || rva > size_) {
			return nullptr;
		}
		auto iter = std::find_if(sections_.begin(), sections_.end(), [rva](const IMAGE_SECTION_HEADER* section) -> bool {
			return section->VirtualAddress <= rva && section->VirtualAddress + section->SizeOfRawData > rva;
		});
		if (iter == sections_.end()) {
			return nullptr;
		}
		else {
			auto item = *iter;
			return data_ + item->PointerToRawData + (rva - item->VirtualAddress);
		}
	}

	uint32_t FindRVAByFileOffset(int offset) {
		DWORD file_offset = static_cast<DWORD>(offset);
		if (!IsLoaded() || offset < 0 || file_offset > size_) {
			return 0;
		}
		auto iter = std::find_if(sections_.begin(), sections_.end(), [file_offset](const IMAGE_SECTION_HEADER* section) -> bool {
			return section->PointerToRawData <= file_offset && section->PointerToRawData + section->SizeOfRawData > file_offset;
		});
		if (iter == sections_.end()) {
			return 0;
		}
		else {
			auto item = *iter;
			return item->VirtualAddress + (file_offset - item->PointerToRawData);
		}
	}

	uint32_t size() const { return size_; }
	const uint8_t * data() const { return data_;}
	uint32_t image_base() const { return image_base_; }
	const std::vector<IMAGE_SECTION_HEADER *>& sections() { return sections_; }
	const std::string& version() { return version_; }
private:
	HANDLE file_;
	HANDLE map_;
	uint32_t size_;
	uint8_t *data_;
	uint32_t image_base_;
	std::vector<IMAGE_SECTION_HEADER *> sections_;
	std::string version_;
};