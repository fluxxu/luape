#pragma once

#include <vector>

struct Segment;
typedef std::vector<Segment> Pattern;

class BytePattern {
public:
	static const int kMaxBytes = 256;

	static Pattern * CreatePattern(const char *pattern);
	static void DestroyPattern(Pattern *pattern);
	static const void * Find(Pattern *pattern, const void *range_begin, size_t size);
};
