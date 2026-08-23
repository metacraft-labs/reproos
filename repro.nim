## ReproOS project graph.
##
## Package modules define build artifacts. The workflow module defines tests
## and interactive commands over those artifacts.

import repro_project_dsl

import "./apps/reproos-installer/package" as installerPackage
import "./recipes/reproos-iso/package" as isoPackage
import "./recipes/reproos-image/package" as imagePackage
import "./recipes/reproos-container/package" as containerPackage
import "./repro/workflows" as workflows

package reproos:
  defaultToolProvisioning "from-source"

  build:
    installerPackage.buildReproosInstallerPackage()
    isoPackage.buildReproosIsoPackage()
    imagePackage.buildReproosImagePackage()
    containerPackage.buildReproosContainerPackage()
    workflows.buildReproosWorkflowsPackage()
    discard collect("default", targets = @[
      BuildTargetDef(name: "installer"),
      BuildTargetDef(name: "iso"),
      BuildTargetDef(name: "image"),
      BuildTargetDef(name: "incus-image"),
    ])
