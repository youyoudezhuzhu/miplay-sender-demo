#!/usr/bin/env python3
"""verify_auth_vectors.py -- regression vectors for the MiPlay WFD authMsgAck.

Every vector below was captured from live hardware. `authMsgAck` is a plain
standard HMAC-SHA256 over ASCII:

    authMsgAck = HMAC-SHA256(key = authKey, msg = authMsg)

authKey is `uuid[:16]` from ProtocolSession.getKey() (the SDK prints it in
logcat), delivered to the receiver via SET_MIRROR_KEY.

Vectors include a session captured AFTER a tablet reboot, which shows the key is
regenerated per session rather than being account-bound.
"""
import hashlib
import hmac
import sys

# (label, authKey, authMsg, authMsgAck)
VECTORS = [
    # pre-reboot, session at 15:31:47 (both directions)
    ('B/dir0', '769a326df0ac49f0', '794a11ae931cbcd1dc9068624a642a39',
     '611bfd79439f357502f31fe0077c66d6dbe05d5a340198341359d154b0f87af8'),
    ('B/dir1', '769a326df0ac49f0', '47fe880cf6852fe762c5d5e894172029',
     '9c1e29b0147c2be4d9c5f796796fef9aa6c533823046283302a02aa34f3833be'),
    # pre-reboot, session at 15:32:32 (both directions)
    ('A/dir0', '2feb068001324c98', '25e1d5733eff0008f56e81eb04eb87a8',
     '889f8b7adb2e8c03dd8259a9b5e822bda053400210d67cafc3dcebebe7dc5d58'),
    ('A/dir1', '2feb068001324c98', '7f490a69948c805f992d461bb4f2faee',
     '1ff0c8da8c3a346438bfd86794959ae366a4ee5c204d8dd5fc383f532958ed19'),
    # POST-REBOOT session at 15:57:36 — two challenges, same key
    ('R1/a', '621b613181a74036', 'aac91bef7067fd3a45ed6171734018e2',
     '467160036375363885533bc775aec1131eb75a1b3478782e824540e45be1dbe6'),
    ('R1/b', '621b613181a74036', '70569569b3f56863cc0e9249409f46ed',
     '573103dd9702307ff50a604a145cab41028bbc1253c7d2fb1aa975da27d02ec3'),
    # POST-REBOOT session at 15:57:41
    ('R2/a', '55626959fb4b4702', '2d93df91917482effd24987f3ab1f248',
     '138f21d2bbffc621a83e4f9b25604acd073be3ca6695d130eea8ca441ce3df22'),
]


def main():
    ok = 0
    for label, key, msg, ack in VECTORS:
        calc = hmac.new(key.encode('ascii'), msg.encode('ascii'),
                        hashlib.sha256).hexdigest()
        good = calc == ack
        ok += good
        print('%-8s %-18s %s' % (label, key, 'MATCH' if good else 'MISMATCH'))
        if not good:
            print('    expected %s\n    got      %s' % (ack, calc))
    print('\n%d/%d vectors verified' % (ok, len(VECTORS)))
    return 0 if ok == len(VECTORS) else 1


if __name__ == '__main__':
    sys.exit(main())
