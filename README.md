# Captured QR Agent

## 한국어

Captured QR Agent는 GNOME/Linux 데스크톱에서 스크린샷 폴더와 클립보드 이미지를 감시하다가 QR 코드를 발견하면 내용을 열거나 클립보드에 복사해 주는 백그라운드 도구입니다. 프로젝트는 QR 감지 데몬과 설정용 GTK 컨트롤 패널로 구성되어 있으며, AppRun3 번들로 패키징됩니다.

### 주요 기능

- 스크린샷 폴더에 새로 저장되는 이미지에서 QR 코드 감지
- `clipboardd`, `wl-paste`, `xclip` 등을 통한 클립보드 이미지 감지
- OpenCV, pyzbar, `zbarimg` 순서로 QR 디코딩 시도
- QR 내용이 열 수 있는 URL 또는 파일 경로이면 열기, 그렇지 않으면 복사
- GNOME 알림에서 기본 동작 또는 복사 동작 실행
- GTK 컨트롤 패널에서 감지 방식, 감시 폴더, URL 스킴, 알림 설정 관리

### 프로젝트 구조

```text
.
├── daemon.apprunxproj/          # QR 감지 데몬 AppRun 프로젝트
│   ├── main.py                  # 감시, 디코딩, 알림, CLI 로직
│   ├── requirements.txt         # Python 런타임 의존성
│   └── AppRunMeta/meta.json     # AppRun 메타데이터와 apt 의존성
├── control-app.apprunxproj/     # GTK 설정 앱 AppRun 프로젝트
│   ├── main.py                  # 컨트롤 패널 UI와 설정 저장 로직
│   └── AppRunMeta/meta.json
├── package.sh                   # 두 AppRun 번들을 빌드하는 스크립트
├── capturedqragentd.apprunx     # 빌드된 데몬 번들
└── CapturedQRAgent-Controller.apprunx
```

### 요구 사항

이 프로젝트는 Linux/GNOME 환경을 대상으로 합니다. 데몬 AppRun 메타데이터에는 다음 apt 패키지가 선언되어 있습니다.

```text
python3-gi
gir1.2-gtk-4.0
gir1.2-glib-2.0
zbar-tools
libzbar0t64
wl-clipboard
xclip
xdg-utils
```

Python 의존성은 데몬 프로젝트의 `requirements.txt`에 있습니다.

```bash
pip install -r daemon.apprunxproj/requirements.txt
```

### 실행

데몬을 직접 실행하려면:

```bash
python3 daemon.apprunxproj/main.py
```

AppRun 번들을 사용하려면:

```bash
apprun3 capturedqragentd.apprunx
```

GUI 시작 서비스로 설치하고 바로 시작하려면:

```bash
apprun3 capturedqragentd.apprunx --install
```

컨트롤 패널을 실행하려면:

```bash
python3 control-app.apprunxproj/main.py
```

또는:

```bash
apprun3 CapturedQRAgent-Controller.apprunx
```

### 수동 QR 스캔

이미지 파일 하나를 스캔하고 QR 내용을 출력할 수 있습니다.

```bash
python3 daemon.apprunxproj/main.py --scan /path/to/image.png
```

설정된 동작까지 실행하려면 `--execute`를 함께 사용합니다.

```bash
python3 daemon.apprunxproj/main.py --scan /path/to/image.png --execute
```

### 설정

공유 설정 파일 위치는 다음 명령으로 확인할 수 있습니다.

```bash
python3 daemon.apprunxproj/main.py --config-path
```

기본 위치는 다음과 같습니다.

```text
~/.config/captured-qr-agent/settings.json
```

기본 설정 파일을 생성하려면:

```bash
python3 daemon.apprunxproj/main.py --write-default-config
```

컨트롤 패널에서 설정을 저장한 뒤, 감시 폴더나 감지 방식 변경을 적용하려면 데몬을 재시작하세요. 컨트롤 패널에는 데몬 재시작 버튼이 포함되어 있습니다.

주요 설정 항목:

- `action_mode`: `smart`, `always_copy`, `always_open`
- `notify_on_detection`: QR 감지 시 GNOME 알림 표시 여부
- `copy_after_open`: 링크나 파일을 연 뒤 QR 내용도 복사할지 여부
- `detection_methods`: `gio`, `inotify`, `clipboardd`, `clipboard_tools`
- `watch_dirs`: 감시할 스크린샷/이미지 폴더 목록
- `open_url_schemes`: 열 수 있는 URL 스킴 목록
- `scan_existing_on_start`: 데몬 시작 시 기존 이미지도 스캔할지 여부

### 패키징

AppRun3 패키징 도구가 설치되어 있으면 다음 스크립트로 두 번들을 생성합니다.

```bash
./package.sh
```

생성되는 파일:

- `CapturedQRAgent-Controller.apprunx`
- `capturedqragentd.apprunx`

### 데모

저장소에는 `CapturedQRAgent Demo.mp4` 데모 영상이 포함되어 있습니다.

---

## English

Captured QR Agent is a background utility for GNOME/Linux desktops. It watches screenshot folders and clipboard images, detects QR codes, then opens supported links/files or copies the decoded text to the clipboard. The project contains a QR detection daemon and a GTK control panel, packaged as AppRun3 bundles.

### Features

- Detects QR codes from newly saved images in screenshot folders
- Detects clipboard images through `clipboardd`, `wl-paste`, `xclip`, and related clipboard tools
- Tries QR decoding with OpenCV, pyzbar, then `zbarimg`
- Opens supported URLs or file paths, and copies other QR contents
- Shows GNOME notifications with default and copy actions
- Provides a GTK control panel for detection methods, watched folders, URL schemes, and notification settings

### Project Layout

```text
.
├── daemon.apprunxproj/          # QR detection daemon AppRun project
│   ├── main.py                  # Monitoring, decoding, notification, and CLI logic
│   ├── requirements.txt         # Python runtime dependency list
│   └── AppRunMeta/meta.json     # AppRun metadata and apt dependencies
├── control-app.apprunxproj/     # GTK settings app AppRun project
│   ├── main.py                  # Control panel UI and settings writer
│   └── AppRunMeta/meta.json
├── package.sh                   # Builds both AppRun bundles
├── capturedqragentd.apprunx     # Built daemon bundle
└── CapturedQRAgent-Controller.apprunx
```

### Requirements

This project targets Linux/GNOME environments. The daemon AppRun metadata declares these apt packages:

```text
python3-gi
gir1.2-gtk-4.0
gir1.2-glib-2.0
zbar-tools
libzbar0t64
wl-clipboard
xclip
xdg-utils
```

Python dependencies are listed in `daemon.apprunxproj/requirements.txt`.

```bash
pip install -r daemon.apprunxproj/requirements.txt
```

### Running

Run the daemon directly:

```bash
python3 daemon.apprunxproj/main.py
```

Or run the AppRun bundle:

```bash
apprun3 capturedqragentd.apprunx
```

Install and start it as a GUI startup service:

```bash
apprun3 capturedqragentd.apprunx --install
```

Run the control panel:

```bash
python3 control-app.apprunxproj/main.py
```

Or:

```bash
apprun3 CapturedQRAgent-Controller.apprunx
```

### Manual QR Scan

Scan one image file and print the decoded QR content:

```bash
python3 daemon.apprunxproj/main.py --scan /path/to/image.png
```

Run the configured action after scanning with `--execute`:

```bash
python3 daemon.apprunxproj/main.py --scan /path/to/image.png --execute
```

### Configuration

Print the shared settings path:

```bash
python3 daemon.apprunxproj/main.py --config-path
```

The default path is:

```text
~/.config/captured-qr-agent/settings.json
```

Create the default settings file:

```bash
python3 daemon.apprunxproj/main.py --write-default-config
```

After saving settings in the control panel, restart the daemon to apply changes to watched folders or detection methods. The control panel includes a daemon restart button.

Important settings:

- `action_mode`: `smart`, `always_copy`, `always_open`
- `notify_on_detection`: whether to show a GNOME notification when a QR code is detected
- `copy_after_open`: whether to copy QR content after opening a link or file
- `detection_methods`: `gio`, `inotify`, `clipboardd`, `clipboard_tools`
- `watch_dirs`: screenshot/image folders to monitor
- `open_url_schemes`: URL schemes that may be opened
- `scan_existing_on_start`: whether to scan existing images when the daemon starts

### Packaging

With the AppRun3 packaging tool installed, build both bundles with:

```bash
./package.sh
```

Generated files:

- `CapturedQRAgent-Controller.apprunx`
- `capturedqragentd.apprunx`

### Demo

The repository includes a demo video: `CapturedQRAgent Demo.mp4`.
