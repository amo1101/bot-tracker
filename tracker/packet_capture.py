import asyncio
import libvirt
import libvirtaio
from pyshark import LiveCapture
from log import TaskLogger

l = TaskLogger(__name__)

class AsyncLiveCapture(LiveCapture):
    def __init__(self, interface=None, bpf_filter=None, display_filter=None,
                 output_file=None, debug=False):
        #  l.debug(f'capturing on {interface}, bpf_filter:{bpf_filter}, output_file:{output_file}, debug:{debug}')
        super(AsyncLiveCapture, self).__init__(interface=interface,
                                               bpf_filter=bpf_filter,
                                               display_filter=display_filter,
                                               only_summaries=False,
                                               decryption_key=None,
                                               encryption_type='wpa-pwk',
                                               output_file=output_file,
                                               decode_as=None,
                                               disable_protocol=None,
                                               tshark_path=None,
                                               override_prefs=None,
                                               capture_filter=None,
                                               monitor_mode=False,
                                               use_json=False,
                                               use_ek=False,
                                               include_raw=False,
                                               eventloop=None,
                                               custom_parameters=None,
                                               debug=debug)
        self.tshark_process = None

    async def sniff_continuously(self, packet_count=0):
        if self.tshark_process is None:
            self.tshark_process = await self._get_tshark_process(packet_count=packet_count)

        parser = self._setup_tshark_output_parser()
        packets_captured = 0
        data =  b''

        try:
            while True:
                try:
                    packet, data = await parser.get_packets_from_stream(self.tshark_process.stdout,
                                                                        data,
                                                                        got_first_packet=packets_captured > 0)
                except EOFError:
                    self._log.debug("EOF reached")
                    self._eof_reached = True
                    break

                if packet:
                    packets_captured += 1
                    yield packet

                if packet_count and packets_captured >= packet_count:
                    break

                if packets_captured % 100==0:
                    self._log.debug(f"received {packets_captured} packets...")

        finally:
            # TODO: gotta do something?
            pass
