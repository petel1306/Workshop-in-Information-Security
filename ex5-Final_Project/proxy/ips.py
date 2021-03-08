# IPS blade against Apache ZooKeeper Information Disclosure

commands = ['conf', 'cons', 'crst', 'envi', 'ruok', 'srst', 'srvr', 'stat', 'wchs', 'dirs', 'wchp', 'mntr']

whitelist_mode = False

def block_zookeeper_command(message):
    splited = text.split()

    if (len(splited) != 1):
        # Invalid structure. blocks the message
        return False

    command = splited[0]

    if whitelist_mode:
        # Whitelist protection
        if command in commands:
            return True
        else:
            return False

    else:
        # Blacklist protection
        if command in commands:
            return False
        else:
            return True
