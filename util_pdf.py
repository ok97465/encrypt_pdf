"""PDF encrpyt.

@author: ok97465
"""
# Standard library imports
# %% Import
import os.path as osp
from pathlib import Path

# Third party imports
from PyPDF2 import PdfFileReader, PdfFileWriter
from PyPDF2.utils import PyPdfError


def encrypt_pdf(path_pdf: str, path_out: str, password: str):
    """encrpyt_pdf.

    Args:
        path_pdf: path of PDF file.
        path_out: path of output file.
        password: password.

    Returns:
        bool: True means that encryption is successful.

    """
    with open(path_pdf, "rb") as f_in, open(path_out, "wb") as f_out:
        pdfReader = PdfFileReader(f_in)

        pdfWriter = PdfFileWriter()
        for pageNum in range(pdfReader.numPages):
            pdfWriter.addPage(pdfReader.getPage(pageNum))

        pdfWriter.encrypt(password)
        pdfWriter.write(f_out)


if __name__ == "__main__":
    path_out = ""
    try:
        path_pdf = r"d:\CodePy\SarSummary\output\200_IFA_RDA.pdf"
        name, ext = osp.splitext(path_pdf)
        path_out = name + "_encrypted" + ext
        encrypt_pdf(path_pdf, path_out, "71815")
    except (FileNotFoundError, PermissionError) as e:
        print(str(e))
    except PyPdfError as e:
        print(str(e))
        print("Cannot encrypt DRM pdf.")
        Path(path_out).unlink(missing_ok=True)
