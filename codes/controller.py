import switch
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from datetime import datetime

# The base code of the controller was taken from : https://github.com/Chandrahas-Soman/Simple_IDS_using_RYU_SDN_controller_and_Machine_Learning/blob/master/IDS_RyuApp.py
# and https://github.com/scc365/tutorial-ryu/blob/main/controller.py

class CollectTrainingStatsApp(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(CollectTrainingStatsApp, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self.monitor)

    #Asynchronous message
    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]


    def monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)
            hub.sleep(1)


    def request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        try:
            timestamp = datetime.now().timestamp()
            icmp_code = -1
            icmp_type = -1
            tp_src = 0
            tp_dst = 0

            with open("Statsfile.csv", "a+") as file0:
                body = ev.msg.body
                for stat in sorted(
                    [flow for flow in body if (flow.priority == 1)],
                    key=lambda flow: (flow.match.get('eth_type', 0),
                                      flow.match.get('ipv4_src', '0.0.0.0'),
                                      flow.match.get('ipv4_dst', '0.0.0.0'),
                                      flow.match.get('ip_proto', 0))
                ):
                    try:
                        if stat.packet_count < 1000:
                            continue

                        ip_src = stat.match.get('ipv4_src', '0.0.0.0')
                        ip_dst = stat.match.get('ipv4_dst', '0.0.0.0')
                        ip_proto = stat.match.get('ip_proto', 0)

                        if ip_proto == 1:  # ICMP
                            icmp_code = stat.match.get('icmpv4_code', -1)
                            icmp_type = stat.match.get('icmpv4_type', -1)
                        elif ip_proto == 6:  # TCP
                            tp_src = stat.match.get('tcp_src', 0)
                            tp_dst = stat.match.get('tcp_dst', 0)
                        elif ip_proto == 17:  # UDP
                            tp_src = stat.match.get('udp_src', 0)
                            tp_dst = stat.match.get('udp_dst', 0)

                        flow_id = f"{ip_src}{tp_src}{ip_dst}{tp_dst}{ip_proto}"

                        packet_count_per_second = (
                            stat.packet_count / stat.duration_sec
                            if stat.duration_sec > 0 else 0
                        )
                        packet_count_per_nsecond = (
                            stat.packet_count / stat.duration_nsec
                            if stat.duration_nsec > 0 else 0
                        )
                        
                        byte_count_per_second = (
                            stat.byte_count / stat.duration_sec
                            if stat.duration_sec > 0 else 0
                        )
                        byte_count_per_nsecond = (stat.byte_count/stat.duration_nsec if stat.duration_nsec > 0 else 0)

                        file0.write(
                            f"{timestamp},{ev.msg.datapath.id},{flow_id},"
                            f"{ip_src},{tp_src},{ip_dst},{tp_dst},{ip_proto},"
                            f"{icmp_code},{icmp_type},{stat.duration_sec},"
                            f"{stat.duration_nsec},{stat.idle_timeout},"
                            f"{stat.hard_timeout},{stat.flags},{stat.packet_count},"
                            f"{stat.byte_count},{packet_count_per_second},"
                            f"{packet_count_per_nsecond},{byte_count_per_second},{byte_count_per_nsecond},1,\n"
                        )
                    except KeyError as e:
                        self.logger.error(f"KeyError in flow stats: {e}")
                    except ZeroDivisionError:
                        self.logger.error("ZeroDivisionError in flow stats")
        except Exception as e:
            self.logger.error(f"Unhandled exception in _flow_stats_reply_handler: {e}")

