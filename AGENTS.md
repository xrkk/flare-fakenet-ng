# FakeNet-NG repository guidance

## Output directory policy

Reserve repository-root `dist/` for distributable artifacts such as release ZIPs,
manifests, and package-verification files. Write runtime logs, PCAPs, HTML reports,
build diagnostics, replay output, and acceptance evidence under repository-root
`Logs/`, which is local and gitignored. New launchers and test runners must default
to `Logs/`; an active plan may name a more specific evidence subdirectory there.

## Ubuntu Docker/Wine Windows build environment

When work involves Windows executables, PyInstaller, GUI VM packages, or Windows-Python tests, inspect and reuse the repository's Docker/Wine builder before declaring that Ubuntu lacks a Windows build environment.

- Image tag: `flare-fakenet-ng/gui-vm-diagnostic-builder:py3119-pyi6220`
- Definition: `tools/docker/gui-vm-diagnostic/Dockerfile`
- Environment: Wine, Windows Python 3.11.9, PyInstaller 6.22.0, pytest 8.3.5, and the pinned project dependencies.
- Rebuild or verify the image from the repository root with `./Build-GuiVmDiagnosticPackage.sh --image-only`. This mode must not create or overwrite a ZIP.
- Check whether the image already exists with `docker image inspect flare-fakenet-ng/gui-vm-diagnostic-builder:py3119-pyi6220` before rebuilding it. On 2026-08-26 the locally verified image ID was `sha256:1b33b518a7c71ecd13264f0d1c41faf254e301b8702e2da8ca11376cff700a5e`; treat this ID as historical evidence and re-read the current image identity when it matters.
- Run Windows-Python tests in this environment with the command shape fixed by the active plan, normally mounting the repository at `/workspace` and invoking `xvfb-run -a wine 'C:\Python311\python.exe' -m pytest ...`.

The current Linux wrapper without arguments builds only `v33-diagnostic-03` through `tools/build_gui_vm_diagnostic_wine.py`. That builder intentionally creates the diagnostic one-file/debug package and must not be presented as a formal v34 acceptance build.

The formal acceptance contract lives in `Build-GuiVmPackage.ps1` and currently produces the v34 onedir package. The Docker image contains the Windows Python/PyInstaller compilation toolchain, but the repository currently has no Linux/Docker wrapper that reproduces the formal PowerShell packaging path. Absence of host `powershell.exe` therefore means the formal wrapper still needs an authorized Docker-compatible entry, not that Windows PE compilation or Windows-Python testing is unavailable. Inspect the active plan and implementation boundary before adding or changing that entry.

This image successfully compiled and assembled the formal v34 onedir package from commit `851fe8fb26a1d5d1148bebb3bc0cb2f2eb69db9a` on 2026-08-26 by using a temporary compatibility entry that reproduced the PowerShell packaging contract. The durable artifact identity and verification evidence are in `PLAN/2026.08.26/2026.08.26-01-v33实机问题分阶段修复方案-实施记录.md` §5.4 and §9. Treat that result as proof that formal compilation is possible in Docker, while continuing to derive each future package's identity and rules from its active plan.

Real Windows VM execution remains necessary for WinDivert, Windows GUI/process-handle behavior, route restoration, and end-to-end Windows-to-Ubuntu Sentinel acceptance. Do not use Wine-only results as substitutes for those runtime acceptance conditions.

## Approved-plan implementation retries

While implementing an already reviewed plan whose status is `已审核, 可以实施`, an in-scope failure found by build or acceptance evidence may be corrected, committed as a new intermediate source snapshot, and rebuilt without asking the user for repeated authorization. Keep each retry mechanically attributable to the active plan and recorded evidence, preserve unrelated work and failed artifacts, use a distinct output directory when a package name would collide, and update the implementation record. An intermediate commit or successful build does not make an ACC pass; continue through the required real-environment acceptance. This standing authorization covers local commits and rebuilds, not `git push`, branch changes, scope expansion, requirement changes, or destructive replacement of evidence.

## Win10 acceptance VM reset

For repeatable FakeNet-NG acceptance, reset only this verified VMware Workstation VM:

- VMX: `/home/adminn/vmware-machines/win10h2-MalBox-20241110/win10h2-MalBox-20241110.vmx`
- Snapshot: `Snapshot 183-FakenetNG测试专用`
- Verified guest identity: computer `DESKTOP-3FI41GR`, MAC `00:0c:29:4c:fd:c0`, BIOS UUID `56 4d e0 b3 b2 3d 3d 9f-4d 52 3e c2 2c 4c fd c0`

Before resetting, export any guest-only evidence that must survive into repository-root `Logs/`. Run the following host-session sequence with `/usr/bin/vmrun -T ws`: confirm `list` names the exact VMX; confirm `listSnapshots <vmx> showTree` contains exactly one matching snapshot; `stop <vmx> soft` when the VM is running; confirm it stopped; `revertToSnapshot <vmx> 'Snapshot 183-FakenetNG测试专用'`; then `start <vmx> gui`. A soft-stop failure is a stopping condition: report it instead of escalating to `hard`. Completion requires a successful Win10VM MCP read-only call after startup, normally PowerShell `$env:COMPUTERNAME`, returning `DESKTOP-3FI41GR`. The host command may need the real VMware user session because an isolated process can report zero running VMs.
