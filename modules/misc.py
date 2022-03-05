import git
from colorama import Fore, Style
from alive_progress import alive_bar


class CloneProgress(git.RemoteProgress):
    OP_CODES = [
        "BEGIN",
        "CHECKING_OUT",
        "COMPRESSING",
        "COUNTING",
        "END",
        "FINDING_SOURCES",
        "RECEIVING",
        "RESOLVING",
        "WRITING",
    ]
    OP_CODE_MAP = {
        getattr(git.RemoteProgress, _op_code): _op_code for _op_code in OP_CODES
    }

    def __init__(self):
        """
        Default constructor.
        :param self.
        :return: None.
        """
        super().__init__()
        self.curr_op = None
        self.alive_bar_instance = None

    @classmethod
    def get_curr_op(cls, op_code: int) -> str:
        """Get OP name from OP code."""
        op_code_masked = op_code & cls.OP_MASK
        return cls.OP_CODE_MAP.get(op_code_masked, "?").title()

    def update(self, op_code, cur_count, max_count=None, message=""):
        """
        Updates the progress bar.
        :param message:
        :param op_code:
        :param max_count:
        :param cur_count:
        :return: None.
        """
        if op_code & self.BEGIN:
            self.curr_op = self.get_curr_op(op_code)
            self._dispatch_bar(title=self.curr_op)

        self.bar(cur_count / max_count)
        self.bar.text(message)

        if op_code & git.RemoteProgress.END:
            self._destroy_bar()

    def _dispatch_bar(self, title):
        """Create a new progress bar"""
        self.alive_bar_instance = alive_bar(manual=True, title=title)
        self.bar = self.alive_bar_instance.__enter__()

    def _destroy_bar(self):
        """Destroy an existing progress bar"""
        self.alive_bar_instance.__exit__(None, None, None)


# Colour Function Defintions
def print_green(text):
    """

    :param text.
    :return: None.
    """
    text = Fore.GREEN + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE
    return text


def print_red(text):
    """

    :param text.
    :return: None.
    """
    text = Fore.RED + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE
    return text


def print_yellow(text):
    """

    :param text.
    :return: None.
    """
    text = Fore.YELLOW + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE
    return text
