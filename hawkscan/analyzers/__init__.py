"""Analyzer registry. Each analyzer inspects a file and yields Findings."""

from .base import Analyzer, AnalysisContext
from .entropy import EntropyAnalyzer
from .strings_analyzer import StringsAnalyzer
from .pe_analyzer import PEAnalyzer
from .elf_analyzer import ELFAnalyzer
from .macho_analyzer import MachOAnalyzer
from .capability_analyzer import CapabilityAnalyzer
from .office_analyzer import OfficeAnalyzer
from .pdf_analyzer import PDFAnalyzer
from .rtf_analyzer import RTFAnalyzer
from .binprofile import BinProfileAnalyzer
from .script_analyzer import ScriptAnalyzer
from .archive_analyzer import ArchiveAnalyzer
from .email_analyzer import EmailAnalyzer
from .pcap_analyzer import PcapAnalyzer
from .android_analyzer import AndroidAnalyzer
from .carver import Carver
from .yara_analyzer import YaraAnalyzer

# Order matters: StringsAnalyzer populates ctx.cache["strings"], which the
# ELF and Mach-O analyzers consume. It must run before any analyzer that
# reads that cache, so it sits right after entropy and before the format ones.
ALL_ANALYZERS: list[type[Analyzer]] = [
    EntropyAnalyzer,
    StringsAnalyzer,
    PEAnalyzer,
    ELFAnalyzer,
    MachOAnalyzer,
    CapabilityAnalyzer,  # after PE/ELF/Mach-O so it can read imports + strings
    BinProfileAnalyzer,
    OfficeAnalyzer,
    PDFAnalyzer,
    RTFAnalyzer,
    ScriptAnalyzer,
    ArchiveAnalyzer,
    EmailAnalyzer,
    PcapAnalyzer,
    AndroidAnalyzer,
    Carver,
    YaraAnalyzer,
]

__all__ = ["Analyzer", "AnalysisContext", "ALL_ANALYZERS"]
