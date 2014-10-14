/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * PENIS */
var nThen = require('nthen');
var Fs = require('fs');
var Spawn = require('child_process').spawn;
var Dhcpjs = require('dhcpjs');

/** A file containing the username on the first line and password on the second. */
var USER_PASS = '/home/user/freebox_auth.txt';

/** The wlan device to use. */
var WLAN_DEV = 'wlan3';

/** This is the ip address of wifi.free.fr. */
var PORTAL_ADDR = '212.27.40.236'; // wifi.free.fr

/** Create routes to each of these addresses, whatever kind of vpn you use. */
var VPN_ROUTES = ['64.15.65.123', '185.19.105.26' ];

/** This node will be periodically pinged to check if the connection is working. */
var PING_TEST = '64.15.65.123';


/** Network tools. */
var IFCONFIG = '/sbin/ifconfig';
var BASH = '/bin/bash';
var STDBUF = '/usr/bin/stdbuf';
var IWCONFIG = '/sbin/iwconfig';
var IWLIST = '/sbin/iwlist';
var RFKILL = '/usr/sbin/rfkill';
var TCPDUMP = '/usr/sbin/tcpdump';
var IP = '/sbin/ip';
var CURL = '/usr/bin/curl';
var PING = '/bin/ping';

/*********************** The Code *************************/

var NOFUNC = function () { };


var now = function () { return (new Date()).getTime(); };

var printLns = function (str, outLineCb) {
    var i = str.indexOf('\n');
    if (i === -1) { return str; }
    var line = str.substring(0,i);
    console.log(Math.floor(now() / 1000) + ' ' + line);
    outLineCb(line);
    return printLns(str.substring(i+1), outLineCb);
};

var bash = function (argStr, cb, outLineCb) {
    outLineCb = outLineCb || NOFUNC;
    console.log('+ ' + argStr);
    var bash = Spawn(STDBUF, [ '-o', 'L', BASH, '-c', argStr ]);
    var err = '';
    var out = '';
    var outc = '';
    bash.stdout.on('data', function (dat) {
        out = printLns(out + dat.toString(), outLineCb);
        outc += dat.toString();
    });
    bash.stderr.on('data', function (dat) { err = printLns(err + dat.toString(), NOFUNC); });
    bash.on('close', function (ret) {
        if (err !== '') { console.log(err); }
        if (out !== '') { console.log(out); }
        cb(ret, outc);
    });
    return bash;
};

var resetDevice = function (cb) {
    nThen(function (waitFor) {
        bash([
            IFCONFIG + ' ' + WLAN_DEV + ' down;',
            RFKILL + ' block wifi;',
            RFKILL + ' unblock wifi;',
            IFCONFIG + ' ' + WLAN_DEV + ' up;'
        ].join('\n'), waitFor());
    }).nThen(function (waitFor) {
        // let the kernel settle...
        setTimeout(cb, 100);
    });
};

var getAccessPoints = function (cb) {
    var scanOut;
    nThen(function (waitFor) {
        bash(IWLIST + ' ' + WLAN_DEV + ' scan', waitFor(function (ret, stdout) {
            if (ret) { throw new Error(ret); }
            scanOut = stdout.split('\n');
        }, true)); 
    }).nThen(function (waitFor) {
        var out = [];
        var addr = '';
        var quality = '';
        scanOut.forEach(function (line) {
            var words = line.split(/\s+/);
            if (words[1] === 'Cell') { addr = words[5]; }
            if (words[2] === 'Signal') { quality = words[1].replace(/^.*=|\/.*/g, ''); }
            if (words[1] === 'ESSID:"FreeWifi"') { out.push({quality: quality, addr:addr}); }
        });
        cb(out);
    });
};

var isConnected = function (cb) {
    bash(IWCONFIG + ' ' + WLAN_DEV + ' | grep "Not-Associated"', cb);
};

var connectAps = function (apsList, cb) {
    //iwconfig wlan3 essid FreeWifi ap AE:F1:4D:98:11:EA
    var i = 0;
    var next = function () {
        if (!apsList[i]) { cb(1); return; }
        console.log("Attempting to connect to [" + apsList[i].addr + ']');
        nThen(function (waitFor) {
            bash(IWCONFIG + ' ' + WLAN_DEV + ' essid FreeWifi ap ' + apsList[i].addr, waitFor());
        }).nThen(function (waitFor) {
            var startTime = now();
            var int = setInterval(function () {
                isConnected(waitFor(function (ret) {
                    if (ret) {
                        console.log("Win!");
                        cb(0);
                            cb = NOFUNC;
                    } else if (now() - startTime > 3000) {
                        i++;
                        next();
                    } else {
                        return;
                    }
                    clearTimeout(int);
                }));
            }, 100);
        });
    };
    next();
};

var dhcpKeepalive = function (dhcp, myIp, cb) {
    var pkt = dhcp.client.createPacket({
        op:     0x01,
        htype:  0x01,
        hlen:   0x06,
        hops:   0x00,
        xid:    (dhcp.xid++ & 0x7fffffff),
        secs:   0x0000,
        flags:  0x0000,
        ciaddr: myIp,
        yiaddr: '0.0.0.0',
        siaddr: '0.0.0.0',
        giaddr: '0.0.0.0',
        chaddr: dhcp.macAddr,
        options: {
            dhcpMessageType: Dhcpjs.Protocol.DHCPMessageType.DHCPREQUEST,
            clientIdentifier: dhcp.clientIdentifier,
        }
    });

    dhcp.client.broadcastPacket(pkt, undefined, cb);
};

var dhcpSetup = function (dhcp, cb) {
    var num = 0;
    dhcp.xid++;
    var gotOffer = false;
    var serverId;
    var gateway;
    var myIp;
    var gotAck;
    var int = setInterval(function () {
        if (num++ > 100 || (!gotOffer && num > 10)) {
            tcpdump.kill();
            cb();
            cb = NOFUNC;
            clearTimeout(int);
        }
        if (!gotOffer) {
            var discover = dhcp.client.createDiscoverPacket({
                xid: dhcp.xid & 0x7fffffff,
                chaddr: dhcp.macAddr,
                options: {
                    dhcpMessageType: Dhcpjs.Protocol.DHCPMessageType.DHCPDISCOVER,
                    clientIdentifier: dhcp.clientIdentifier,
                }
            });
            dhcp.client.broadcastPacket(discover, undefined, NOFUNC);
        } else if ((num % 2)) {
            // There is a bug in free's infrastructure which will respond to Discover
            // messages offering IPs which are already held (by you) and then NACK you when
            // you try to Request it, so we send half requests and half keepalives in order
            // to handle both cases (either we're in their cache or not).
            dhcpKeepalive(dhcp, myIp, NOFUNC);
        } else {
            var request = dhcp.client.createDiscoverPacket({
                xid: dhcp.xid & 0x7fffffff,
                chaddr: dhcp.macAddr,
                options: {
                    dhcpMessageType: Dhcpjs.Protocol.DHCPMessageType.DHCPREQUEST,
                    requestedIpAddress: myIp,
                    serverIdentifier: serverId
                }
            });
            dhcp.client.broadcastPacket(request, undefined, NOFUNC);
        }
    }, 1000);

    var tcpdump = bash(TCPDUMP + ' -e -v -n -i ' + WLAN_DEV, NOFUNC, function (line) {
        if (gotAck) { return; }
        gateway = (line.match(/Gateway-IP ([0-9\.]+)/) || [])[1] || gateway;
        myIp = (line.match(/Your-IP ([0-9\.]+)/) || [])[1] || myIp;
        serverId = (line.match(/Server-ID Option 54, length 4: ([0-9\.]+)/) || [])[1] || serverId;
        if (/ DHCP-Message Option 53, length 1: Offer/.test(line)) {
            gotOffer = true;
            num = 0;
        }
        if (!(myIp && gateway && serverId)) { return; }
        if (/DHCP-Message Option 53, length 1: ACK/.test(line)) {
            gotAck = true;
            console.log('Got ip['+ myIp +'] and gateway['+gateway+']!');
            tcpdump.kill();
            clearTimeout(int);
            cb({myIp: myIp, gateway: gateway, serverId: serverId});
            cb = NOFUNC;
        }
    });
};

var flush = function (cb) {
    nThen(function (waitFor) {
        bash(IP + ' route flush all;', waitFor());
        bash(IP + ' addr flush dev ' + WLAN_DEV, waitFor());
    }).nThen(cb);
};

var setupRoutes = function (dhcp, cb) {
    var dhcpInfo;
    nThen(function (waitFor) {
        flush(waitFor());
    }).nThen(function (waitFor) {
        bash(IP + ' route add 255.255.255.255 dev ' + WLAN_DEV, waitFor());
    }).nThen(function (waitFor) {
        dhcpSetup(dhcp, waitFor(function (di) {
            dhcpInfo = di;
            if (!dhcpInfo) {
                waitFor.abort();
                bash(IP + ' route flush all;', cb);
            }
        }));
    }).nThen(function (waitFor) {
        flush(waitFor());
    }).nThen(function (waitFor) {
        bash(IP + ' addr add ' + dhcpInfo.myIp + ' dev ' + WLAN_DEV, waitFor());
    }).nThen(function (waitFor) {
        bash(IP + ' route add dev tun0;', waitFor());
    }).nThen(function (waitFor) {
        bash(IP + ' route add 255.255.255.255 dev ' + WLAN_DEV, waitFor());
    }).nThen(function (waitFor) {
        bash(IP + ' route add ' + dhcpInfo.gateway + ' dev ' + WLAN_DEV, waitFor());
    }).nThen(function (waitFor) {
        var nt = nThen;
        var ips = [ PING_TEST ];
        VPN_ROUTES.forEach(function (peer) { if (ips.indexOf(peer) === -1) { ips.push(peer); } });
        ips.forEach(function (ip) {
            nt = nt(function (waitFor) {
                bash(IP + ' route add ' + ip + ' via ' + dhcpInfo.gateway + ';', waitFor());
            }).nThen;
        });
        nt(waitFor());
    }).nThen(function (waitFor) {
        cb(dhcpInfo);
    });
};

var getCurrentAp = function (cb) {
    bash(IWCONFIG + ' ' + WLAN_DEV, function (ret, stdout) {
        cb((stdout.match(/Access Point: ([a-fA-F0-9\:]+)/) || [])[1]);
    });
};

var pingTest = function (timeoutMilliseconds, cb) {
    var timeOfLastPing = now();
    var startTime = timeOfLastPing;
    var ping = bash(PING + ' ' + PING_TEST, NOFUNC, function (line) {
        if (line.indexOf('64 bytes from') !== -1) {
            timeOfLastPing = now();
        }
    });
    var iv = setInterval(function () {
        if (now() - timeOfLastPing > timeoutMilliseconds) {
            ping.kill();
            clearTimeout(iv);
            cb(timeOfLastPing - startTime);
        }
    }, 1000)
};


var doPostCredentials = function (user, pass, cb) {
    return bash(CURL + ' \
        --resolve wifi.free.fr:80:' + PORTAL_ADDR + ' \
        --data "login=' + user + '&password=' + pass + '&submit=Valider" \
        --connect-timeout 10 \
        --max-redirs 0 \
        "https://wifi.free.fr/Auth"', cb);
};

var postCredentials = function (user, pass, gateway, cb) {
    var dpc;
    nThen(function (waitFor) {
        bash(IP + ' route add ' + PORTAL_ADDR + ' via ' + gateway, waitFor());
    }).nThen(function (waitFor) {
        var ping = bash(PING + ' ' + PING_TEST, waitFor(), function (line) {
            if (line.indexOf('64 bytes from') !== -1) {
                ping.kill();
                cb(0);
                cb = NOFUNC;
            }
        });
        var initTime = now();
        var again = function () {
            if (cb === NOFUNC) { return; }
            if (now() - initTime > 20000) {
                ping.kill();
                cb(1);
                cb = NOFUNC;
                return;
            }
            dpc = doPostCredentials(user, pass, again);
        };
        again();
    }).nThen(function (waitFor) {
        if (dpc) { dpc.kill(); }
        bash(IP + ' route del ' + PORTAL_ADDR + ' via ' + gateway, waitFor());
    });
};

var main = function () {
    var dhcp = {
        client: new Dhcpjs.Client(),
        xid: now(),
        clientIdentifier: 'cjd@cjdns.fr',
        macAddr: ''
    };
    var user;
    var pass;

    var apsList;
    var again = function (fastRecovery) {
        console.log(new Date());
        if (fastRecovery) {
            console.log("Attempting a fast recovery");
        }

        var dhcpInfo;
        nThen(function (waitFor) {
            if (fastRecovery) { return; }
            console.log('Resetting ' + WLAN_DEV);
            resetDevice(waitFor());
        }).nThen(function (waitFor) {
            if (fastRecovery) { return; }
            console.log("Searching for APs");
            getAccessPoints(waitFor(function (aps) {
                console.log(JSON.stringify(aps, null, '  '));
                apsList = aps;
            }));
        }).nThen(function (waitFor) {
            connectAps(apsList, waitFor(function (ret) {
                if (ret) {
                    waitFor.abort();
                    setTimeout(again);
                }
            }));
        }).nThen(function (waitFor) {
            console.log("Requesting IP addresses and creating routes");
            setupRoutes(dhcp, waitFor(function (di) {
                if (!di) {
                    waitFor.abort();
                    setTimeout(again);
                }
                dhcpInfo = di;
            }));
        }).nThen(function (waitFor) {
            console.log("Posting Credentials");
            postCredentials(user, pass, dhcpInfo.gateway, waitFor(function (ret) {
                if (ret !== 0) {
                    waitFor.abort();
                    setTimeout(again);
                }
            }));
        }).nThen(function (waitFor) {
            var keepaliveInt = setInterval(function () {
                dhcpKeepalive(dhcp, dhcpInfo.myIp, NOFUNC);
            }, 10000);
            var currentAp;
            getCurrentAp(waitFor(function (ap) { currentAp = ap; }));
            pingTest(5000, waitFor(function (time) {
                clearTimeout(keepaliveInt);
                if (time > 20000 && currentAp) {
                    // the connection has been working for some time...
                    // attempt a fast recovery
                    for (var i = 0; i < apsList.length; i++) {
                        if (apsList[i].addr !== currentAp) { continue; }
                        var x = apsList[i];
                        apsList[i] = apsList[0];
                        apsList[0] = x;
                        break;
                    }
                    waitFor.abort();
                    again(true);
                }
            }));
        }).nThen(function (waitFor) {
            setTimeout(again);
        });
    };

    nThen(function (waitFor) {
        Fs.readFile(USER_PASS, waitFor(function (err, ret) {
            if (err) { throw err; }
            ret = ret.toString('utf8').split('\n');
            user = ret[0];
            pass = ret[1];
        }));
    }).nThen(function (waitFor) {
        console.log('Binding DHCP');
        dhcp.client.bind('0.0.0.0', 68, waitFor());
    }).nThen(function (waitFor) {
        console.log('Getting ' + WLAN_DEV + ' mac');
        bash(IFCONFIG + ' ' + WLAN_DEV, waitFor(function (ret, stdout) {
            dhcp.macAddr = stdout.match(/HWaddr ([a-f0-9\:]+)/)[1];
            console.log(dhcp.macAddr);
        }));
    }).nThen(function (waitFor) {
        again();
    });
};


main();
