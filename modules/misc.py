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
        :param:
        :return:
        """
        super().__init__()
        self.curr_op = None
        self.alive_bar_instance = None

    @classmethod
    def get_curr_op(cls, op_code: int) -> str:
        """
        Gets the OP name from OP code.
        :param cls:
        :param op_code:
        :return cls.OP_CODE_MAP.get(op_code_masked, "?").title():
        """
        op_code_masked = op_code & cls.OP_MASK
        return cls.OP_CODE_MAP.get(op_code_masked, "?").title()

    def update(self, op_code, cur_count, max_count=None, message=""):
        """
        Updates the progress bar.
        :param message:
        :param op_code:
        :param max_count:
        :param cur_count:
        :return:
        """
        if op_code & self.BEGIN:
            self.curr_op = self.get_curr_op(op_code)
            self._dispatch_bar(title=self.curr_op)

        self.bar(cur_count / max_count)
        self.bar.text(message)

        if op_code & git.RemoteProgress.END:
            self._destroy_bar()

    def _dispatch_bar(self, title):
        """
        Create new progress bar.
        :param title:
        :return:
        """
        self.alive_bar_instance = alive_bar(manual=True, title=title)
        self.bar = self.alive_bar_instance.__enter__()

    def _destroy_bar(self):
        """
        Destroy progress bar.
        :return:
        """
        self.alive_bar_instance.__exit__(None, None, None)


# Colour function definitions.
def print_green(text):
    """
    Returns the text in the colour green.
    :param text:
    :return text:
    """
    text = Fore.GREEN + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE
    return text


def print_red(text):
    """
    Returns the text in the colour red.
    :param text:
    :return: text:
    """
    text = Fore.RED + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE
    return text


def print_yellow(text):
    """
    Returns the text in the colour yellow.
    :param text:
    :return: text:
    """
    text = Fore.YELLOW + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE
    return text
