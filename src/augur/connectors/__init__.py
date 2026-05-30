from augur.connectors.base import Sink, SinkBase, Source
from augur.connectors.runner import run_hunt
from augur.connectors.sinks import (CortexXsoarSink, JiraSink, JsonlFileSink, SlackSink,
                                           StdoutSink, WebhookSink)
from augur.connectors.sources import DirectorySource, HttpSource, JsonlSource, StdinSource

SOURCES = {"jsonl": JsonlSource, "directory": DirectorySource, "stdin": StdinSource,
           "http": HttpSource}
SINKS = {"stdout": StdoutSink, "jsonl": JsonlFileSink, "webhook": WebhookSink, "slack": SlackSink,
         "jira": JiraSink, "xsoar": CortexXsoarSink}


def get_source(name: str, **kwargs) -> Source:
    return SOURCES[name](**kwargs)


def get_sink(name: str, **kwargs) -> Sink:
    return SINKS[name](**kwargs)


__all__ = ["Source", "Sink", "SinkBase", "run_hunt", "get_source", "get_sink", "SOURCES", "SINKS"]
