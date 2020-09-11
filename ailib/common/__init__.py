from ast import literal_eval
import os
import yaml


# colors = {'blue': '36', 'red': '31', 'green': '32', 'yellow': '33', 'pink': '35', 'white': '37'}
def error(text):
    color = "31"
    print('\033[0;%sm%s\033[0;0m' % (color, text))


def warning(text):
    color = "33"
    print('\033[0;%sm%s\033[0;0m' % (color, text))


def info(text):
    color = "36"
    print('\033[0;%sm%s\033[0;0m' % (color, text))


def success(text):
    color = "32"
    print('\033[0;%sm%s\033[0;0m' % (color, text))


def get_overrides(paramfile=None, param=[]):
    """

    :param paramfile:
    :param param:
    :return:
    """
    overrides = {}
    if paramfile is not None and os.path.exists(os.path.expanduser(paramfile)):
        with open(os.path.expanduser(paramfile)) as f:
            try:
                overrides = yaml.safe_load(f)
            except:
                error("Couldn't parse your parameters file %s. Leaving" % paramfile)
                os._exit(1)
    if param is not None:
        for x in param:
            if len(x.split('=')) < 2:
                continue
            else:
                if len(x.split('=')) == 2:
                    key, value = x.split('=')
                else:
                    split = x.split('=')
                    key = split[0]
                    value = x.replace("%s=" % key, '')
                if value.isdigit():
                    value = int(value)
                elif value.lower() == 'true':
                    value = True
                elif value.lower() == 'false':
                    value = False
                elif value == '[]':
                    value = []
                elif value.startswith('[') and value.endswith(']'):
                    if '{' in value:
                        value = literal_eval(value)
                    else:
                        value = value[1:-1].split(',')
                        for index, v in enumerate(value):
                            v = v.strip()
                            value[index] = v
                overrides[key] = value
    return overrides
