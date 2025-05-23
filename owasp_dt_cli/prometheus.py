from prometheus_client import Gauge, Enum, CollectorRegistry, Summary, PROCESS_COLLECTOR, PLATFORM_COLLECTOR, GC_COLLECTOR

from owasp_dt_cli.log import LOGGER

type Instrument = Gauge | Enum | Summary


class PrometheusAdapter:
    def __init__(self, metrics_prefix:str ="owasp_dtrack_"):
        self.__prefix = metrics_prefix

    def disable_python_metrics(self, registry: CollectorRegistry):
        try:
            registry.unregister(PROCESS_COLLECTOR)
            registry.unregister(PLATFORM_COLLECTOR)
            registry.unregister(GC_COLLECTOR)
        except Exception as e:
            LOGGER.error(f"Failed unregistering python metrics: {e}")

    def prefix_metric_key(self, metric_key: str):
        return f"{self.__prefix}{metric_key}"

    def remove_by_label(self, instrument: Instrument, match_labels: dict):
        for label_tuple in list(instrument._metrics.keys()):
            label_names = instrument._labelnames
            label_dict = dict(zip(label_names, label_tuple))

            if all(label_dict.get(k) == v for k, v in match_labels.items()):
                instrument.remove(*label_tuple)
