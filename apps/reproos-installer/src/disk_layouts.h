// The installer's view of the ReproOS disk-layout registry.
//
// This translation unit deliberately depends on nothing but the C++
// standard library and the generated table in disk_layouts_generated.h.
// Two reasons, both load-bearing:
//
//  1. It renders nothing. Every document it returns is a preset's
//     rendered template from repro/disk_layouts.nim with the three
//     per-install parameters substituted. The installer used to carry
//     its own JSON emitter and its own "only uefi-ext4 is supported"
//     literal, and both had drifted from the registry the image build
//     applies; there is now one declaration and one renderer.
//
//  2. It is Qt-free on purpose, so tests/test_installer_disk_layout_parity.nim
//     can compile *this* file -- the shipped one, not a copy -- with a
//     bare g++ and compare its output byte for byte against the Nim
//     registry, without needing a Qt toolchain to be present.
//
// The validation messages are the registry's own, reproduced exactly;
// the parity gate compares them string for string against
// validateDiskLayoutRequest's, so "refused with a generic message"
// cannot pass.

#pragma once

#include <string>
#include <vector>

namespace reproos {

// Metadata for one registered layout, copied out of the generated table.
struct DiskLayoutInfo {
    std::string name;
    std::string summary;
    bool buildable = false;
    std::string unbuildableReason;
    int minDiskSizeGb = 0;
    int defaultEspSizeMib = 0;
};

// Registration order, which is the order every error message lists.
std::vector<DiskLayoutInfo> diskLayoutPresets();

// True when `name` is a registered preset, buildable or not.
bool diskLayoutIsRegistered(const std::string &name);

// Look the preset up; returns false when it is not registered.
bool findDiskLayoutPreset(const std::string &name, DiskLayoutInfo *out);

// The default layout name and the numeric defaults, from the registry.
std::string defaultDiskLayoutName();
int defaultEspSizeMib();
int defaultDiskSizeGb();
int minEspSizeMib();

// "" when the request is installable, otherwise the registry's own
// operator-facing reason -- byte-identical to what
// repro/disk_layouts.nim's validateDiskLayoutRequest returns for the
// same inputs.
std::string validateDiskLayout(const std::string &name, int espSizeMib,
                               int diskSizeGb);

// The disko document repro disk apply consumes, and the hardware.nim
// profile source installed at /etc/repro/hardware.nim. Both are the
// registry's rendering with `id`, `device` and `espSizeMib` substituted.
// An unregistered name returns "" -- callers validate first.
std::string renderDiskoDocument(const std::string &name,
                                const std::string &id,
                                const std::string &device, int espSizeMib);
std::string renderHardwareNim(const std::string &name, const std::string &id,
                              const std::string &device, int espSizeMib);

}  // namespace reproos
