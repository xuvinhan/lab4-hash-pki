#pragma once

#include <string>

bool generate_md5_collision_samples(
    const std::string& out1,
    const std::string& out2
);

bool compare_md5_collision_files(
    const std::string& file1,
    const std::string& file2
);
