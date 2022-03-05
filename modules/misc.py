import git
from colorama import Fore, Style


class CloneProgress(git.RemoteProgress):
    def __init__(self):
        """
        Default constructor.
        :param self.
        :return: None.
        """
        super().__init__()
        self.alive_bar_instance = None

    def update(self, cur_count, max_count=None):
        """
        Updates the progress bar.
        :param cur_count, max_count.
        :return: None.
        """
        self.alive_bar_instance.total = max_count
        self.alive_bar_instance.n = cur_count
        self.alive_bar_instance.refresh()


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
