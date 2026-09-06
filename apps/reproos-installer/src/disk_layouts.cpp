// See disk_layouts.h for why this file exists and why it is Qt-free.

#include "disk_layouts.h"

#include "disk_layouts_generated.h"

#include <string>

namespace reproos {
namespace {

// The registry escapes strings on its way into a document; a value
// substituted into an already-rendered template has to be escaped the
// same way or the two sides would agree on ordinary device names and
// disagree on awkward ones. These are the rules
// repro/disk_layouts.nim's jsonStr applies, and the parity gate feeds
// both sides a value containing a quote and a backslash so that a
// divergence here is caught rather than assumed away.
std::string escapeForDocument(const std::string &value) {
    std::string out;
    out.reserve(value.size());
    for (char c : value) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\t': out += "\\t"; break;
        case '\r': out += "\\r"; break;
        default: out += c; break;
        }
    }
    return out;
}

std::string replaceAll(std::string text, const std::string &needle,
                       const std::string &replacement) {
    if (needle.empty()) return text;
    std::string::size_type at = 0;
    while ((at = text.find(needle, at)) != std::string::npos) {
        text.replace(at, needle.size(), replacement);
        at += replacement.size();
    }
    return text;
}

std::string substitute(const char *tmpl, const std::string &id,
                       const std::string &device, int espSizeMib) {
    std::string out(tmpl);
    out = replaceAll(out, generated::IdPlaceholder, escapeForDocument(id));
    out = replaceAll(out, generated::DevicePlaceholder,
                     escapeForDocument(device));
    out = replaceAll(out, generated::EspMibPlaceholder,
                     std::to_string(espSizeMib));
    return out;
}

const generated::DiskLayoutPreset *lookup(const std::string &name) {
    for (int i = 0; i < generated::DiskLayoutPresetCount; ++i) {
        if (name == generated::DiskLayoutPresets[i].name)
            return &generated::DiskLayoutPresets[i];
    }
    return nullptr;
}

// repro/disk_layouts.nim quotes offending values with its JSON string
// escaper; the messages below have to match byte for byte, so quote
// them the same way.
std::string quoted(const std::string &value) {
    return "\"" + escapeForDocument(value) + "\"";
}

}  // namespace

std::vector<DiskLayoutInfo> diskLayoutPresets() {
    std::vector<DiskLayoutInfo> presets;
    presets.reserve(generated::DiskLayoutPresetCount);
    for (int i = 0; i < generated::DiskLayoutPresetCount; ++i) {
        const generated::DiskLayoutPreset &p = generated::DiskLayoutPresets[i];
        DiskLayoutInfo info;
        info.name = p.name;
        info.summary = p.summary;
        info.buildable = p.buildable;
        info.unbuildableReason = p.unbuildableReason;
        info.minDiskSizeGb = p.minDiskSizeGb;
        info.defaultEspSizeMib = p.defaultEspSizeMib;
        presets.push_back(info);
    }
    return presets;
}

bool diskLayoutIsRegistered(const std::string &name) {
    return lookup(name) != nullptr;
}

bool findDiskLayoutPreset(const std::string &name, DiskLayoutInfo *out) {
    const generated::DiskLayoutPreset *p = lookup(name);
    if (p == nullptr) return false;
    if (out != nullptr) {
        out->name = p->name;
        out->summary = p->summary;
        out->buildable = p->buildable;
        out->unbuildableReason = p->unbuildableReason;
        out->minDiskSizeGb = p->minDiskSizeGb;
        out->defaultEspSizeMib = p->defaultEspSizeMib;
    }
    return true;
}

std::string defaultDiskLayoutName() {
    return generated::DefaultDiskLayoutName;
}

int defaultEspSizeMib() { return generated::DefaultEspSizeMib; }
int defaultDiskSizeGb() { return generated::DefaultDiskSizeGb; }
int minEspSizeMib() { return generated::MinEspSizeMib; }

std::string validateDiskLayout(const std::string &name, int espSizeMib,
                               int diskSizeGb) {
    // The order of these checks is the registry's order, not a
    // convenient one: an operator who mistypes the layout name must be
    // told that first, whichever other value is also wrong.
    const generated::DiskLayoutPreset *preset = lookup(name);
    if (preset == nullptr) {
        return "unknown [disk.layout].type: " + quoted(name) + "\n" +
               "  legal values:\n" + generated::LegalDiskLayoutListing;
    }
    if (espSizeMib < generated::MinEspSizeMib) {
        return "[disk.layout].esp_size_mib must be an integer of at least " +
               std::to_string(generated::MinEspSizeMib) + " (got " +
               std::to_string(espSizeMib) + ")";
    }
    if (diskSizeGb < 0) {
        return "[disk] size_gb must be an integer";
    }
    if (diskSizeGb < preset->minDiskSizeGb) {
        return "[disk] size_gb = " + std::to_string(diskSizeGb) +
               " is too small for layout " + quoted(preset->name) +
               ", which needs at least " +
               std::to_string(preset->minDiskSizeGb) + " GB";
    }
    if (!preset->buildable) {
        return "[disk.layout].type " + quoted(preset->name) +
               " is declared but not yet buildable: " +
               preset->unbuildableReason + "\n  build with " +
               quoted(generated::DefaultDiskLayoutName) + " until then";
    }
    return "";
}

std::string renderDiskoDocument(const std::string &name,
                                const std::string &id,
                                const std::string &device, int espSizeMib) {
    const generated::DiskLayoutPreset *preset = lookup(name);
    if (preset == nullptr) return "";
    return substitute(preset->documentTemplate, id, device, espSizeMib);
}

std::string renderHardwareNim(const std::string &name, const std::string &id,
                              const std::string &device, int espSizeMib) {
    const generated::DiskLayoutPreset *preset = lookup(name);
    if (preset == nullptr) return "";
    return substitute(preset->hardwareTemplate, id, device, espSizeMib);
}

}  // namespace reproos
