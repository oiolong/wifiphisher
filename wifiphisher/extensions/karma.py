"""
Extension that check victims associated with rogue AP by KARMA attack
"""

import itertools
from collections import defaultdict


class Karma(object):
    """
    Handles for printing KARMA attack information
    """

    def __init__(self, data):
        """
        Setup the class with all the given arguments.

        :param self: A Karma object.
        :param data: Shared data from main engine
        :type self: Karma
        :type data: dictionary
        :return: None
        :rtype: None
        """
        self._data = data
        self._packets_to_send = defaultdict(list)
        self._mac2ssid_dict = defaultdict()
        self._roundrobin_macssids = itertools.cycle([])

    def get_packet(self, packet):
        """
        :param self: A Karma object
        :param packet: A scapy.layers.RadioTap object
        :type self: Karma
        :type packet: scapy.layers.RadioTap
        :return: empty list
        :rtype: list
        """
        return self._packets_to_send

    def send_output(self):
        """
        Send the output the extension manager
        :param self: A Karma object.
        :type self: Karma
        :return: A list with the password checking information
        :rtype: list
        ..note: In each packet we ask roguehostapd whether there are victims
        associated to rogue AP
        """
        info = []
        is_change = False
        if not self._data.args.force_hostapd:
            ssid_mac_list = self._data.roguehostapd.get_karma_data()
            try:
                mac_list, ssid_list = zip(*ssid_mac_list)
            except ValueError:
                # incase ssid_mac_list is still empty
                mac_list = []
                ssid_list = []
            # remove the one not in the current associated list
            pop_macs = []
            for mac in self._mac2ssid_dict:
                if mac not in mac_list:
                    is_change = True
                    pop_macs.append(mac)
            for key in pop_macs:
                self._mac2ssid_dict.pop(key)
            # add new associated victims to the dictionary
            for idx, mac in enumerate(mac_list):
                if mac not in self._mac2ssid_dict:
                    is_change = True
                    self._mac2ssid_dict[mac] = ssid_list[idx]
            # renewl the round robin cycle if the mac2ssid dictionary
            # has changed
            if is_change:
                self._roundrobin_macssids = itertools.cycle(
                    self._mac2ssid_dict.items())
            try:
                macssid_pair = self._roundrobin_macssids.next()
                mac = macssid_pair[0]
                ssid = macssid_pair[1]
                info = ["KARMA Target SSID: " + ssid + "/Victim MAC: " + mac]
            except StopIteration:
                pass
        return info

    def send_channels(self):
        """
        Send channels to subscribe
        :param self: A Karma object.
        :type self: Karma
        :return: empty list
        :rtype: list
        ..note: we don't need to send frames in this extension
        """

        return [self._data.target_ap_channel]

    def on_exit(self):
        """
        Free all the resources regarding to this module
        :param self: A Handshakeverify object.
        :type self: Handshakeverify
        :return: None
        :rtype: None
        """
        pass
