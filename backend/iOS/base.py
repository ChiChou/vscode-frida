IGNORE = ['-oStrictHostKeyChecking=no', '-oUserKnownHostsFile=/dev/null', '-oUserKnownHostsFile=/dev/null']


class BaseTool(object):
    def __init__(self, port: int, host='localhost', user='root'):
        self.port = port
        self.host = host
        self.user = user

    def ssh(self, *args):
        return ['ssh'] + IGNORE + ['-q', '-p%d' % self.port, '%s@%s' % (self.user, self.host)] + list(args)

    def scp(self, src: str, dst: str, direction='down'):
        prefix = '%s@%s:' % (self.user, self.host)
        if direction == 'down':
            src = prefix + src
        elif direction == 'up':
            dst = prefix + dst
        else:
            raise ValueError('invalid direction: %s' % direction)

        return ['scp'] + IGNORE + ['-P%d' % self.port] + [src, dst]
