from pyshark import LiveCapture, LiveRingCapture, FileCapture

from log import TaskLogger

l: TaskLogger = TaskLogger(__name__)


class AsyncLiveCapture(LiveCapture):
    def __init__(self, interface=None, bpf_filter=None, display_filter=None,
                 output_file=None, debug=False):
        #  l.debug(f'capturing on {interface}, bpf_filter:{bpf_filter}, output_file:{output_file}, debug:{debug}')
        super(AsyncLiveCapture, self).__init__(interface=interface,
                                               bpf_filter=bpf_filter,
                                               display_filter=display_filter,
                                               output_file=output_file,
                                               debug=debug)
        self.tshark_process = None

    async def sniff_continuously(self, packet_count=0):
        if self.tshark_process is None:
            self.tshark_process = await self._get_tshark_process(packet_count=packet_count)

        parser = self._setup_tshark_output_parser()
        packets_captured = 0
        data = b''

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
        finally:
            self._log.debug("sniff finalized.")


class AsyncLiveRingCapture(LiveRingCapture):
    def __init__(self, ring_file_size=1024*512, num_ring_files=20480, ring_file_name=None,
                 interface=None, bpf_filter=None, display_filter=None,
                 debug=False):
        super(AsyncLiveRingCapture, self).__init__(ring_file_size=ring_file_size,
                                                   num_ring_files=num_ring_files,
                                                   ring_file_name=ring_file_name,
                                                   interface=interface,
                                                   bpf_filter=bpf_filter,
                                                   display_filter=display_filter,
                                                   debug=debug)
        self.tshark_process = None

    async def sniff_continuously(self, packet_count=0):
        if self.tshark_process is None:
            self.tshark_process = await self._get_tshark_process(packet_count=packet_count)

        parser = self._setup_tshark_output_parser()
        packets_captured = 0
        data = b''

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
        finally:
            self._log.debug("sniff finalized.")


class AsyncFileCapture(FileCapture):
    def __init__(self, input_file, display_filter=None, debug=False):
        super(AsyncFileCapture, self).__init__(input_file=input_file,
                                               display_filter=display_filter,
                                               debug=debug)

    async def sniff_continuously(self, packet_count=0):
        self.tshark_process = await self._get_tshark_process(packet_count=packet_count)
        parser = self._setup_tshark_output_parser()
        packets_captured = 0
        data = b''

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
        finally:
            self._log.debug("sniff finalized.")

