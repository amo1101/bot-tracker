import asyncio
import libvirt
import libvirtaio
import libxml2
import pyshark

class AsyncLiveCapture(LiveCapture):
    async def sniff_continuously(self, packet_count):
        tshark_process = await self._get_tshark_process(packet_count=packet_count)
        parser = self._setup_tshark_output_parser()
        packets_captured = 0
        data =  b''

        while True:
            try:
                packet, data = await parser.get_packets_from_stream(tshark_process.stdout,
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

