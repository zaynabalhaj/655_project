import switch
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from datetime import datetime
import pandas as pd
import joblib
import ipaddress

class CollectTrainingStatsApp(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(CollectTrainingStatsApp, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self.monitor)

        # Load ML model and preprocessors
        self.model = joblib.load('RF_model.pkl')
        self.encoder = joblib.load('encoder.pkl')
        self.scaler = joblib.load('scaler.pkl')

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
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
            hub.sleep(2)
		self.flow_predict()

    def request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def process_live_data(self, df):
        # Process the data for prediction
		
		df = pd.read_csv("flow_stats.csv")
        df = df.drop(['Timestamp', 'flow_id', 'idle_timeout', 'hard_timeout', 'flags',
                          'icmp_code', 'packet_count_per_nsecond', 'byte_count_per_nsecond'], axis=1)

		# Create dictionaries to store mappings
		src_ip_mapping = {}
		dst_ip_mapping = {}



		# Convert IP addresses to integers and create mappings
		df['ip_src'] = df['ip_src'].apply(
			lambda ip: src_ip_mapping.setdefault(ip, int(ipaddress.IPv4Address(ip)))
		)
		df['ip_dst'] = df['ip_dst'].apply(
			lambda ip: dst_ip_mapping.setdefault(ip, int(ipaddress.IPv4Address(ip)))
		)
			
		src_int_to_ip = {int(ip): original_ip for original_ip, ip in src_ip_mapping.items()}
		dst_int_to_ip = {int(ip): original_ip for original_ip, ip in dst_ip_mapping.items()}

        cat_vars = ['ip_proto', 'icmp_type']
        encoded_vars = self.encoder.transform(data[cat_vars])
        encoded_df = pd.DataFrame(encoded_vars.toarray(), columns=self.encoder.get_feature_names_out(cat_vars))

        data.drop(cat_vars, axis=1, inplace=True)
        data = pd.concat([data, encoded_df], axis=1)
        data.fillna(0, inplace=True)
        return self.scaler.transform(data)

    def predict_traffic(self, live_data):
        X_live = self.process_live_data(live_data)
		predictions = self.model.predict(X_scaled)
            normal_traffic = (predictions == 0).sum()
            dos_traffic = (predictions == 1).sum()
            port_scanning = (predictions == 2).sum()

            if (normal_traffic / len(predictions) * 100) > 50:
                print("Traffic is NORMAL.")
            elif dos_traffic > port_scanning:
                print("DDoS traffic detected!")
            else:
                print("Port scanning detected!")



            # Print source and destination IPs for non-normal traffic
            abnormal_indices = (predictions != 0)
            abnormal_traffic = df[abnormal_indices]
            # Print source and destination IPs for non-normal traffic without reprinting
            printed_ips = set()  # Track printed (src, dst) pairs

            try:
                for index, row in abnormal_traffic.iterrows():
                    ip_pair = (row['ip_src'], row['ip_dst'])
                    
                    # Decode the integer IPs back to original IP strings
                    original_src_ip = src_int_to_ip.get(int(row['ip_src']), f"Unknown ({row['ip_src']})")
                    original_dst_ip = dst_int_to_ip.get(int(row['ip_dst']), f"Unknown ({row['ip_dst']})")

                    # Use the decoded original IPs for tracking and printing
                    decoded_ip_pair = (original_src_ip, original_dst_ip)
                    
                    if decoded_ip_pair not in printed_ips:
                        print(f"Traffic Source IP: {original_src_ip}, Destination IP: {original_dst_ip}")
                        printed_ips.add(decoded_ip_pair)

            except Exception as e:
                print("")


    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Handle flow stats reply."""

        try:
            
            # File path
            csv_file = 'flow_stats.csv'

            # Headers
            headers = [
                "Timestamp", "datapath_id", "flow_id", "ip_src", "tp_src",
                "ip_dst", "tp_dst", "ip_proto", "icmp_code", "icmp_type",
                "duration_sec", "duration_nsec", "idle_timeout", "hard_timeout",
                "flags", "packet_count", "byte_count", "packet_count_per_second",
                "packet_count_per_nsecond", "byte_count_per_second", "byte_count_per_nsecond"
            ]

            # Check if file exists; if not, create it and write headers
            if not os.path.exists(csv_file):
                with open(csv_file, mode='w') as file:
                    file.write(','.join(headers) + '\n')
                    #print(f"CSV file '{csv_file}' created with headers.")

            # Collect flow data
            timestamp = datetime.now().timestamp()
            body = ev.msg.body
            icmp_code = 0
            icmp_type = 0
            tp_src = 0
            tp_dst = 0
            with open(csv_file, mode='a') as file: 
                for stat in sorted(
                        [flow for flow in body if (flow.priority == 1)],
                        key=lambda flow: (flow.match.get('eth_type', 0),
                                          flow.match.get('ipv4_src', '0.0.0.0'),
                                          flow.match.get('ipv4_dst', '0.0.0.0'),
                                          flow.match.get('ip_proto', 0))
                ):
       
                    # Extract flow data
                    ip_src = stat.match.get('ipv4_src', '0.0.0.0')
                    ip_dst = stat.match.get('ipv4_dst', '0.0.0.0')
                    ip_proto = stat.match.get('ip_proto', 0)
                    if ip_proto == 1:  # ICMP
                        icmp_code = stat.match.get('icmpv4_code', 0)
                        icmp_type = stat.match.get('icmpv4_type', 0)
                    elif ip_proto == 6:  # TCP
                        tp_src = stat.match.get('tcp_src', 0)
                        tp_dst = stat.match.get('tcp_dst', 0)
                    elif ip_proto == 17:  # UDP
                        tp_src = stat.match.get('udp_src', 0)
                        tp_dst = stat.match.get('udp_dst', 0)

                    # Calculate additional stats
                    packet_count_per_second = (stat.packet_count / stat.duration_sec
                                               if stat.duration_sec > 0 else 0)
                    packet_count_per_nsecond = (stat.packet_count / stat.duration_nsec
                                                if stat.duration_nsec > 0 else 0)
                    byte_count_per_second = (stat.byte_count / stat.duration_sec
                                             if stat.duration_sec > 0 else 0)
                    byte_count_per_nsecond = (stat.byte_count / stat.duration_nsec
                                              if stat.duration_nsec > 0 else 0)

                    flow_id = f"{ip_src}-{tp_src}-{ip_dst}-{tp_dst}"


                    file.write(
                        f"{timestamp},{ev.msg.datapath.id},{flow_id},{ip_src},{tp_src},"
                        f"{ip_dst},{tp_dst},{ip_proto},{icmp_code},{icmp_type},"
                        f"{stat.duration_sec},{stat.duration_nsec},{stat.idle_timeout},"
                        f"{stat.hard_timeout},{stat.flags},{stat.packet_count},"
                        f"{stat.byte_count},{packet_count_per_second},"
                        f"{packet_count_per_nsecond},{byte_count_per_second},{byte_count_per_nsecond}\n"
                    )
        except Exception as e:
            print(f"Error in flow_stats_reply_handler: {e}")



               