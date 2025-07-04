import argparse
from event import *

# DEVICES = [
#     "Apple iPhone6",
#     "Huawei P9Lite",
#     "Xiaomi Note8T",
#     "Oneplus Nord5G",
#     "Xiaomi Mi9Lite",
#     "Apple iPhone13Pro",
#     "Apple iPhone14Pro",
#     "Apple iPhone11",
#     "Apple iPad8",
#     "Apple MacM1",
#     "Apple iPhone7",
#     "Apple MacAir",
#     "Samsung Note20Ultra",
#     "Lenovo Thinkpadx13Gen1",
# ]

DEVICE_CHOSEN = {
    "Apple iPhone11": 3,
    "Apple iPhone13Pro": 3,
    "Apple iPhone14Pro": 3,
    "Apple iPhone7": 3,
    "Samsung Note20Ultra": 3,
    "Xiaomi Mi9Lite": 3,
    "Xiaomi Note8T": 3,
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Pass the arguments for the simulation')

    parser.add_argument('-o', '--out_file', type=str, help='Path to the output file', required=True)
    parser.add_argument('-n', '--average_number_of_devices', type=int, help='Average number of devices', required=True)
    parser.add_argument('-pt', '--average_permanence_time', type=int, help='Average permanence time for devices (minutes)', required=True)
    parser.add_argument('-t', '--real_minutes', type=float, help='Duration of the simulation (minutes)', required=True)
    parser.add_argument('-c', '--closed_environment', action="store_true", help='Set a closed environment for devices')
    parser.add_argument('-s', '--sniffers', type=int, default=0, help='Number of sniffers in the simulation')
    parser.add_argument('-snp', '--sniffer_positions', type=str, default=None, help='2D position of sniffers in the simulation (e.g., "0,0;1,1;2,2")')
    parser.add_argument('-em', '--enable_mobility', action="store_true", help='Enable mobility for devices')

    args = parser.parse_args()

    # Access the parsed arguments
    out_file = args.out_file
    average_number_of_devices = args.average_number_of_devices
    average_permanence_time = args.average_permanence_time
    real_minutes = args.real_minutes
    closed_environment = args.closed_environment
    enable_mobility = args.enable_mobility
    sniffers = args.sniffers
    sniffer_positions = args.sniffer_positions

    start_time = datetime.now()
    simulator = Simulator(
        out_file,
        avg_number_of_devices=average_number_of_devices,
        avg_permanence_time=average_permanence_time*60,
        closed_environment=closed_environment
    )

    print(start_time)

    print('+++++++++++\nStart simulation\n+++++++++++')

    last_time = None

    sniffer_list = list()
    positions = sniffer_positions.split(';')
    for i in range(sniffers):
        if sniffer_positions is not None:
            pos = positions[i].split(',')
            x, y = float(pos[0]), float(pos[1])
        else:
            x, y = 0, 0
        sniffer = Sniffer((x, y), id=i+1)
        sniffer.start()
        sniffer_list.append(sniffer)
    
    for k, value in DEVICE_CHOSEN.items():
        add_new_event(simulator, Event(start_time, "create_device", vendor=k.split(" ")[0], model=k.split(" ")[1], enable_mobility=enable_mobility, sniffers=sniffer_list))

    
    with open(simulator.out_file + '.txt', 'a') as f:
        f.write('+++++++++++Simulation start+++++++++++\n')
        f.write('Initial time (real and simulated): {}\n'.format(start_time))

    while datetime.now() < start_time + timedelta(seconds=real_minutes * 60) and len(simulator.events_list) > 0:
        event = simulator.events_list.pop(0)  # take the first event from the list
        last_time = event.start_time
        handle_event(event, simulator)  # handle the event

    end_time = datetime.now()
    alive_devices = [ev.device.id for ev in simulator.events_list if ev.device is not None]
    for device in simulator.devices_list:
        if device.id in alive_devices:
            delete_device(simulator, device, last_time)

    print("\n+++++++++++\nSimulation end\n+++++++++++")
    print(end_time)

    different_MACs = 0
    num_pkts = 0
    for device in simulator.devices_list:
        device.print_information(simulator.out_file)
        device.print_statistics(simulator.out_file)
        num_pkts += device.number_packets_sent
        different_MACs += len(device.mac_address)

    with open(simulator.out_file + '.txt', 'a') as f:
        f.write('\n+++++++++++Simulation end+++++++++++\n')
        f.write('End time (real): {}\n'.format(end_time))
        f.write('End time (simulated): {}\n'.format(last_time))
        f.write(
            'Time ratio (simulated/real): {}\n'.format(round((last_time - start_time) / (end_time - start_time), 2)))
        f.write('List of devices and statistics\n')
        f.write('\nTotal number of different MAC addresses: ' + str(different_MACs) + '\n')
        f.write('Total number of packets sent: ' + str(num_pkts) + '\n')
