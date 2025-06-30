from scapy.layers.dot11 import RadioTap
from numpy import log10

STANDARD_RSSI = 20
REFERENCE_DISTANCE = 1
REFERENCE_LOSS = 46.67
EXPONENT = 3

class Sniffer:
    def __init__(self, position: tuple, id: int):
        self.position = position
        self.started = False
        self.id = id

    def start(self):
        self.started = True

    def stop(self):
        self.started = False

    def receive_packet(self, packet, sender):
        if self.started:
            # Modify the rssi value based on the sniffer's position (the initial set value was randomly chosen)
            position = sender.x_values[-1], sender.y_values[-1]
            distance = ((self.position[0] - position[0]) ** 2 + (self.position[1] - position[1]) ** 2) ** 0.5
            if packet.haslayer(RadioTap):
                rssi = packet[RadioTap].dBm_AntSignal
                pathloss = - 10 * EXPONENT * log10(distance / REFERENCE_DISTANCE) - REFERENCE_LOSS
                adjusted_rssi = STANDARD_RSSI + pathloss
                packet[RadioTap].dBm_AntSignal = adjusted_rssi
            return packet
        return None