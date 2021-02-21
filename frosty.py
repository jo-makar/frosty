#!/usr/bin/env python3

from elastic import main_elastic
from minimal import main_minimal

import argparse
import logging
import os


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s:%(levelname)s:%(name)s:%(threadName)s:%(message)s')

    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', '-d', action='store_true')

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('--minimal', '--min', '-m', action='store_true')
    mode_group.add_argument('--elastic', '--elk', '-e', action='store_true')

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

        basepath = os.path.dirname(os.path.abspath(__file__))

        class LogFilter(logging.Filter):
            def filter(self, record):
                # Filter out debug logs generated from other modules
                if record.levelname == 'DEBUG':
                    if os.path.dirname(os.path.abspath(record.pathname)) != basepath:
                        return 0
                return 1

        # Log filters don't propagate like the log level
        # https://docs.python.org/3/howto/logging-html#logging-flow
        for handler in logging.root.handlers:
            handler.addFilter(LogFilter())

    if args.minimal:
        logging.info('running in minimal mode')
        main_minimal()

    if args.elastic:
        logging.info('running in elasticsearch mode')
        main_elastic()
