"""PDF 파일에 암호를 설정한다."""
# %% Import
# Standard library imports
import os.path as osp
import sys
from pathlib import Path

# Third party imports
import qdarkstyle
from PyQt5.QtCore import QObject, Qt, QThread, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

# Local imports
from util_pdf import PyPdfError, encrypt_pdf

VER = "0.0.01"


class PdfTableWidget(QTableWidget):
    """PDF 파일 진행 결과를 표시하는 테이블."""

    def __init__(self, parent) -> None:
        """."""
        super().__init__(parent=parent)

        self.setAcceptDrops(True)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)

        col_labels = ["파일명", "진행 여부"]
        self.setColumnCount(len(col_labels))
        self.setHorizontalHeaderLabels(col_labels)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

    def dragEnterEvent(self, event):
        """Drag된 정보가 파일이면 Drop을 활성화 한다."""
        data = event.mimeData()
        urls = data.urls()
        if urls and urls[0].scheme() == "file":
            event.acceptProposedAction()

    def dragMoveEvent(self, event):
        """Drag된 정보가 파일이면 Drop을 활성화 한다."""
        data = event.mimeData()
        urls = data.urls()
        if urls and urls[0].scheme() == "file":
            event.acceptProposedAction()

    def dropEvent(self, event):
        """Drop된 정보가 PDF 파일이면 Table에 추가한다."""
        data = event.mimeData()
        urls = data.urls()
        if urls and urls[0].scheme() != "file":
            return

        for url in urls:
            path = str(url.path())[1:]
            if not osp.isfile(path):
                continue

            filename = osp.split(path)[1]
            if osp.splitext(filename)[1] != ".pdf":
                continue

            item_name = QTableWidgetItem()
            item_name.setData(Qt.DisplayRole, filename)
            item_name.setData(Qt.UserRole, path)
            item_name.setTextAlignment(int(Qt.AlignLeft | Qt.AlignVCenter))

            item_complete = QTableWidgetItem("미수행", Qt.DisplayRole)
            item_complete.setTextAlignment(Qt.AlignCenter)

            idx_row = self.rowCount()
            self.setRowCount(idx_row + 1)
            self.setItem(idx_row, 0, item_name)
            self.setItem(idx_row, 1, item_complete)

    def clear(self):
        """Clear."""
        self.setRowCount(0)


class EncryptThread(QThread):
    """Thread에서 pdf를 암호화 한다."""

    signal_result = pyqtSignal(int, str)

    def __init__(self, parent: QObject, table: QTableWidget):
        """."""
        super().__init__(parent=parent)
        self.table = table
        self.password = ""

    def set_password(self, password: str):
        """암호를 설정한다."""
        self.password = password

    def run(self):
        """PDF를 암호화 한다."""
        table = self.table
        password = self.password

        for idx in range(table.rowCount()):
            path_pdf = table.item(idx, 0).data(Qt.UserRole)
            name, ext = osp.splitext(path_pdf)
            path_out = name + "_encrypted" + ext

            result = "미수행"
            try:
                encrypt_pdf(path_pdf, path_out, password)
                result = "완료"
            except (FileNotFoundError, PermissionError) as e:
                result = str(e)
            except PyPdfError as e:
                result = str(e) + "(DRM PDF는 암호화 불가)"
                Path(path_out).unlink(missing_ok=True)

            self.signal_result.emit(idx, result)


class MainWindow(QMainWindow):
    """MainWindow."""

    def __init__(self) -> None:
        """."""
        super().__init__()
        self.table_path = PdfTableWidget(self)

        self.setWindowTitle(f"Encrypt pdf by ok97465 - {VER}")
        self.setMinimumWidth(700)

        icon_path = osp.abspath(osp.join(osp.dirname(__file__), "ok_64x64.ico"))
        icon = QIcon()
        icon.addPixmap(QPixmap(icon_path), QIcon.Normal, QIcon.Off)
        self.setWindowIcon(icon)

        # 암호 설정 layout
        hbox = QHBoxLayout()
        self.line_password = QLineEdit(self)
        self.btn_run = QPushButton("Run", self)
        self.btn_clear = QPushButton("Clear", self)
        self.btn_run.clicked.connect(self.run_encrypt)
        self.btn_clear.clicked.connect(self.table_path.clear)
        hbox.addWidget(QLabel("Password", self))
        hbox.addWidget(self.line_password)
        hbox.addWidget(self.btn_run)
        hbox.addWidget(self.btn_clear)

        # Path list layout
        vbox = QVBoxLayout()
        vbox.addLayout(hbox)
        vbox.addWidget(self.table_path)

        # 전체 Layout을 설정한다.
        central_widget = QWidget(self)
        central_widget.setLayout(vbox)
        self.setCentralWidget(central_widget)

        # PDF 암호화를 위한 THread를 설정한다.
        self.thread_encrypt = EncryptThread(self, self.table_path)
        self.thread_encrypt.finished.connect(lambda: self.set_enabled_gui(True))
        self.thread_encrypt.signal_result.connect(self.update_result)

    def run_encrypt(self):
        """PDF 암호 추가 작업을 시작한다."""
        password = self.line_password.text()
        if password.strip() == "":
            QMessageBox.critical(self, "암호화 불가", "Password가 비었습니다.")
            return

        if not self.thread_encrypt.isRunning():
            self.set_enabled_gui(False)
            self.thread_encrypt.set_password(password)
            self.thread_encrypt.start()

    def set_enabled_gui(self, state: bool):
        """GUI를 활성화/비활성화 한다."""
        if state is False:
            QApplication.setOverrideCursor(Qt.WaitCursor)
        else:
            QApplication.restoreOverrideCursor()
        self.line_password.setEnabled(state)
        self.btn_run.setEnabled(state)
        self.btn_clear.setEnabled(state)

    @pyqtSlot(int, str)
    def update_result(self, idx_row: int, result: str):
        """PDF 암호화 결과를 표시한다."""
        table = self.table_path
        item = table.item(idx_row, 1)
        item.setData(Qt.DisplayRole, result)


if __name__ == "__main__":
    APP = QApplication(sys.argv)

    style_sheet = qdarkstyle.load_stylesheet_pyqt5()
    APP.setStyleSheet(style_sheet)

    MAIN_WINDOW = MainWindow()

    MAIN_WINDOW.show()

    sys.exit(APP.exec_())
