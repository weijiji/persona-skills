import yaml


def load_profile(data: str):
    return yaml.load(data)


if __name__ == "__main__":
    import sys
    load_profile(sys.argv[1])
