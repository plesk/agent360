from __future__ import print_function
import re, sys, os
import libvirt
import libxml2
import time
import plugins
import psutil

class Plugin(plugins.BasePlugin):
    __name__ = 'vms'

    def run(self, config):
        '''
        Using the libvirt API to fetch statistics from guests
        running KVM, QEMU, Xen, Virtuozzo, VMWare ESX, LXC,
        BHyve and more
        '''
        results = {}
        last_value = {}
        prev_cache = self.get_agent_cache()  # Get absolute values from previous check
        uri = os.getenv("uri", "qemu:///system")
        values = self.fetch_values(uri)

        deltas = {}
        for key, value in values.items():
            deltas[key] = {}
            for subkey, subvalue in value.items():
                if subkey == 'mem_bytes' or subkey == 'soft_limit_bytes' or subkey == 'min_guarantee_bytes' or subkey == 'hard_limit_bytes':
                    deltas[key][subkey] = value[subkey]
                else:
                    deltas[key][subkey] = self.absolute_to_per_second('%s_%s' % (key, subkey), float(subvalue), prev_cache)
                    last_value['%s_%s' % (key, subkey)] = float(value[subkey])
        last_value['ts'] = time.time()
        self.set_agent_cache(last_value)
        return deltas

    def canon(self, name):
        return re.sub(r"[^a-zA-Z0-9_]", "_", name)

    def get_ifaces(self, dom):
        xml = dom.XMLDesc(0)
        doc = None
        try:
            doc = libxml2.parseDoc(xml)
        except:
            return []
        ctx = doc.xpathNewContext()
        ifaces = []
        try:
            ret = ctx.xpathEval("/domain/devices/interface")
            for node in ret:
                devdst = None
                for child in node.children:
                    if child.name == "target":
                        devdst = child.prop("dev")
                if devdst == None:
                    continue
                ifaces.append(devdst)
        finally:
            if ctx != None:
                ctx.xpathFreeContext()
            if doc != None:
                doc.freeDoc()
        return ifaces

    def get_memtune(self, dom):
        memtune = { 'min_guarantee': 0, 'soft_limit': 0, 'hard_limit': 0 }
        xml = dom.XMLDesc(0)

        try:
            doc = libxml2.parseDoc(xml)
        except:
            return []

        ctx = doc.xpathNewContext()
        try:
            for key in memtune:
                ret = ctx.xpathEval("/domain/memtune/%s" % key)
                try:
                    for child in ret[0].children:
                        memtune[key] = int(child.content)
                        break
                except IndexError:
                        # key not found in xml
                        pass
        finally:
            if ctx != None:
                ctx.xpathFreeContext()
            if doc != None:
                doc.freeDoc()
        return memtune

    def fetch_values(self, uri):
        conn = libvirt.openReadOnly(uri)
        ids = conn.listDomainsID()
        results = {}
        for id in ids:
            try:
                name, data = self.fetch_domain_values(conn, id)
            except libvirt.libvirtError as err:
                # A guest that is busy (e.g. holds the state change lock during
                # a live migration) must not abort collection for the other guests.
                # Skip it for this cycle: partial data would produce bogus deltas.
                print("Id: %s: skipped, %s" % (id, err), file=sys.stderr)
                continue
            if name is None:
                continue
            results[self.canon(name)] = data
        return results

    def fetch_domain_values(self, conn, id):
        '''
        Returns (name, data) for a single domain, or (None, None) if the domain
        should be ignored. Raises libvirt.libvirtError if the domain cannot be queried.
        '''
        dom = conn.lookupByID(id)
        name = dom.name()
        if name == "Domain-0":
            return None, None

        data = {}
        data['net_rx_bytes'] = 0
        data['net_tx_bytes'] = 0
        for iface in self.get_ifaces(dom):
            try:
                stats = dom.interfaceStats(iface)
                data['net_rx_bytes'] += stats[0]
                data['net_tx_bytes'] += stats[4]
            except libvirt.libvirtError:
                print("Cannot get ifstats for '%s' on '%s'" % (iface, name), file=sys.stderr)

        info = dom.info()
        cputime = float(info[4])
        cputime_percentage = 1.0e-7 * cputime
        data['cpu'] = cputime_percentage
        try:
            data['cpu_percentage'] = cputime_percentage / psutil.cpu_count()
        except Exception as e:
            pass

        data['mem_bytes'] = info[2] * 1024
        memtune = self.get_memtune(dom)
        data['min_guarantee_bytes'] = memtune['min_guarantee'] * 1024
        data['hard_limit_bytes'] = memtune['hard_limit'] * 1024
        data['soft_limit_bytes'] = memtune['soft_limit'] * 1024

        data['disk_rd_bytes'] = 0
        data['disk_wr_bytes'] = 0
        data['disk_wr_req'] = 0
        data['disk_rd_req'] = 0
        for disk in self.get_disks(dom):
            try:
                rd_req, rd_bytes, wr_req, wr_bytes, errs = dom.blockStats(disk)
            except TypeError:
                print("Cannot get blockstats for '%s' on '%s'" % (disk, name), file=sys.stderr)
                continue
            # libvirtError is deliberately not caught here: if the domain is locked,
            # every further call would block for the libvirt job wait (~120s) too,
            # so give up on the whole domain instead of just this disk.
            data['disk_rd_bytes'] += rd_bytes
            data['disk_wr_bytes'] += wr_bytes
            data['disk_rd_req'] += rd_req
            data['disk_wr_req'] += wr_req

        return name, data

    def get_disks(self, dom):
        xml = dom.XMLDesc(0)
        doc = None
        try:
            doc = libxml2.parseDoc(xml)
        except:
            return []
        ctx = doc.xpathNewContext()
        disks = []
        try:
            ret = ctx.xpathEval("/domain/devices/disk")
            for node in ret:
                devdst = None
                for child in node.children:
                    if child.name == "target":
                        devdst = child.prop("dev")
                if devdst == None:
                    continue
                disks.append(devdst)
        finally:
            if ctx != None:
                ctx.xpathFreeContext()
            if doc != None:
                doc.freeDoc()
        return disks


if __name__ == '__main__':
    Plugin().execute()
