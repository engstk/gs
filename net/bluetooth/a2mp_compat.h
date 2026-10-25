/* SPDX-License-Identifier: GPL-2.0-only */
/*
   Copyright (c) 2010,2011 Code Aurora Forum.  All rights reserved.
   Copyright (c) 2011,2012 Intel Corp.

*/

#ifndef __A2MP_COMPAT_H
#define __A2MP_COMPAT_H

#include <net/bluetooth/l2cap.h>

/*
 * struct amp_mgr was removed 78e40feaee07 ("UPSTREAM: Bluetooth: Remove BT_HS").
 * It was part of the KMI through struct hci_conn, but is not used anywhere
 * now. Restoring the structure for KMI compliance.
 */
struct amp_mgr {
	struct list_head	list;
	struct l2cap_conn	*l2cap_conn;
	struct l2cap_chan	*a2mp_chan;
	struct l2cap_chan	*bredr_chan;
	struct kref		kref;
	__u8			ident;
	__u8			handle;
	unsigned long		state;
	unsigned long		flags;

	struct list_head	amp_ctrls;
	struct mutex		amp_ctrls_lock;
};

#endif /* __A2MP_COMPAT_H */
