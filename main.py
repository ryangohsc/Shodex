import argparse


def main():
    init_argparser()


def init_argparser():
    """
        Initialise the arg parser.
        :param: None
        :return: args
    """
    parser = argparse.ArgumentParser(description="ICT2206 - Codex", epilog="ICT2206 Assignment 1 Team x")
    # parser.add_argument()
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    main()
