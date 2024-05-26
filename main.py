import time
from signal import signal, SIGINT

import yaml
import argparse
import subprocess

from pprint import pprint

fuzzers = []


class AFL:
    def __init__(self, target_type, is_master, index_of_fuzzer_layout=0, custom_arguments=None, custom_ram_limit=None):
        self.__subprocess = None
        self.target_type = target_type
        self.is_master = is_master
        self.index_of_fuzzer_layout = index_of_fuzzer_layout
        self.custom_arguments = custom_arguments
        self.custom_ram_limit = custom_ram_limit
        self.__name_of_fuzzer = f"{target_type}{'_master' if is_master else ''}{'_' if not is_master else ''}{'' if is_master else index_of_fuzzer_layout}"

    def start(self):
        print(f'Starting fuzzer {self.__name_of_fuzzer}')
        command = []
        command.append(config['fuzzer_configs']['afl']['executables']['afl-fuzz'])
        if self.custom_ram_limit is not None:
            if self.custom_ram_limit != 0:
                command.extend(['-m', str(self.custom_ram_limit)])
        elif 'ram_limit' in config['fuzzer_configs']['afl']:
            command.extend(['-m', str(config['fuzzer_configs']['afl']['ram_limit'])])
        if self.is_master:
            command.extend(['-M', self.__name_of_fuzzer])
        else:
            command.extend(['-S', self.__name_of_fuzzer])
        if config['runtime_options']['first_launch']:
            command.extend(['-i', config['fuzzer_configs']['afl']['seeds']])
        else:
            command.extend(['-i', '-'])

        command.extend(['-o', config['fuzzer_configs']['afl']['output_folder']])
        if self.custom_arguments is not None:
            command.extend(self.custom_arguments.split(' '))
        command.append('--')
        command.extend(config['fuzzer_configs']['afl']['targets'][self.target_type])

        pprint(command)

        self.__subprocess = subprocess.Popen(command,
                                             stdin=subprocess.PIPE,
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.STDOUT)

    def stop(self):
        if self.__subprocess is None:
            return

        print(f'Stopping fuzzer {self.__name_of_fuzzer}')
        self.__subprocess.terminate()
        self.__subprocess.communicate()
        self.__subprocess = None

    def check_health(self) -> bool:
        poll = self.__subprocess.poll()
        if poll is not None:
            print(f'Fuzzer {self.__name_of_fuzzer} seems to have crashed!')
            outs, errs = self.__subprocess.communicate()
            pprint(outs)
            pprint(errs)
            return False

        return True


def start_fuzzers():
    # First, start the master fuzzer
    master_index = None
    for i in range(len(fuzzers)):
        if fuzzers[i].is_master:
            master_index = i
            break

    fuzzers[master_index].start()

    # Now, start all the slave fuzzers
    for i in range(len(fuzzers)):
        if fuzzers[i].is_master:
            continue
        fuzzers[i].start()


def stop_fuzzers():
    # First, stop all non-master fuzzers
    for i in range(len(fuzzers)):
        if fuzzers[i].is_master:
            master_index = i
            continue
        fuzzers[i].stop()

    # Now, stop the master.
    fuzzers[master_index].stop()


def main():
    global config

    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, default='config.yml')
    parser.add_argument('--first-launch', action='store_true')
    args = parser.parse_args()

    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)

    pprint(config)

    assert 'runtime_options' not in config
    config['runtime_options'] = {}
    config['runtime_options']['first_launch'] = args.first_launch

    defined_a_master_fuzzer = False

    for fuzzer_layout in config['layout']:
        assert fuzzer_layout['fuzzer'] == 'afl'

        if 'count' not in fuzzer_layout:
            fuzzer_layout['count'] = 1

        if 'is_master' in fuzzer_layout and fuzzer_layout['is_master']:
            assert fuzzer_layout['count'] == 1
            defined_a_master_fuzzer = True
        elif 'is_master' not in fuzzer_layout:
            fuzzer_layout['is_master'] = False

        if 'custom_arguments' not in fuzzer_layout:
            fuzzer_layout['custom_arguments'] = None

        if 'ram_limit' not in fuzzer_layout:
            fuzzer_layout['ram_limit'] = None

        for i in range(fuzzer_layout['count']):
            fuzzers.append(AFL(fuzzer_layout['target_type'],
                               fuzzer_layout['is_master'],
                               i + 1,
                               fuzzer_layout['custom_arguments'],
                               fuzzer_layout['ram_limit']))

    assert defined_a_master_fuzzer

    start_fuzzers()

    should_shutdown = False
    try:
        while not should_shutdown:
            time.sleep(0.5)
            for fuzzer in fuzzers:
                if not fuzzer.check_health():
                    should_shutdown = True
    except KeyboardInterrupt:
        print('Shutting down...')

    stop_fuzzers()


if __name__ == '__main__':
    main()
