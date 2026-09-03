WORK_DIRECTORY = ".runne-product-work"
APP_ZIP_RELATIVE = f"{WORK_DIRECTORY}/app.zip"
DMG_ROOT_RELATIVE = f"{WORK_DIRECTORY}/dmg-root"
DMG_RELATIVE = f"{WORK_DIRECTORY}/Runne.dmg"
OUTPUT_DMG_NAME = "Runne.dmg"
EVIDENCE_NAME = "Runne-signing-evidence.v3.json"


def staged_app_relative(app_name: str) -> str:
    return f"{DMG_ROOT_RELATIVE}/{app_name}"
