/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __USB_IO_BRIDGE_H
#define __USB_IO_BRIDGE_H

/* stub types */
enum stub_type {
	CTRL_STUB = 1,
	DIAG_STUB,
	GPIO_STUB,
	I2C_STUB,
	SPI_STUB,
};

/* CTRL stub commands */
enum usbio_mng_cmd {
	CTRL_PROT_VERSION = 0,
	CTRL_FW_VERSION,
	CTRL_RESET_NOTIFY,
	CTRL_RESET,
	CTRL_POWER_STATE_CHANGE,
	CTRL_SET_DFU_MODE,
	CTRL_ENUM_GPIO = 0x10,
	CTRL_ENUM_I2C,
	CTRL_ENUM_SPI,
};

/* DIAG commands */
enum diag_cmd {
	DIAG_GET_STATE = 1,
	DIAG_GET_STATISTIC,
	DIAG_SET_TRACE_LEVEL,
	DIAG_SET_ECHO_MODE,
	DIAG_GET_FW_LOG,
	DIAG_GET_FW_COREDUMP,
	DIAG_TRIGGER_WDT,
	DIAG_TRIGGER_FAULT,
	DIAG_FEED_WDT,
	DIAG_GET_SECURE_STATE,
};

/* command Flags */
#define ACK_FLAG BIT(0)
#define RESP_FLAG BIT(1)
#define CMPL_FLAG BIT(2)
#define ERR_FLAG BIT(3)

/* Control Transfer Message */
struct usbio_msg {
	u8 type;
	u8 cmd;
	u8 flags;
	u8 len;
	u8 data[];
} __packed;

/* Bulk Transfer Message */
struct usbio_bmsg {
	u8 type;
	u8 cmd;
	u8 flags;
	u16 len;
	u8 data[];
} __packed;

struct fw_version {
	u8 major;
	u8 minor;
	u16 patch;
	u16 build;
} __packed;

struct usbio_i2c_descriptor {
	u8 num;
	struct usbio_i2c_info info[];
} __packed;

struct usbio_spi_ctr_info {
	u8 id;
	u8 capacity;
} __packed;

struct usbio_spi_descriptor {
	u8 num;
	struct usbio_spi_ctr_info info[];
} __packed;

struct usbio_bank_descriptor {
	u8 bank_id;
	u8 pin_num;

	/* 1 bit for each gpio, 1 means valid */
	u32 valid_pins;
} __packed;

struct usbio_gpio_descriptor {
	u8 pins_per_bank;
	u8 banks;
	struct usbio_bank_descriptor bank_desc[];
} __packed;

#define MAX_PACKET_SIZE 64
#define MAX_PAYLOAD_SIZE (MAX_PACKET_SIZE - sizeof(struct usbio_msg))
#define USB_WRITE_TIMEOUT 200
#define USB_WRITE_ACK_TIMEOUT 500
#define USB_ENUM_STUB_TIMEOUT 20

struct usbio_event_cb_entry {
	struct platform_device *pdev;
	usbio_event_cb_t notify;
};

struct usbio_stub_packet {
	u8 *ibuf;
	u32 ibuf_len;
};

struct usbio_stub {
	struct list_head list;
	u8 type;
	struct usb_interface *intf;
	spinlock_t event_cb_lock;

	struct usbio_stub_packet ipacket;

	/* for identify ack */
	bool acked;
	int cur_cmd;

	struct usbio_event_cb_entry event_entry;
};

static inline void *usbio_priv(const struct usbio_stub *stub)
{
	return (char *)stub + sizeof(struct usbio_stub);
}

enum bridge_state {
	BRIDGE_STOPPED,
	BRIDGE_INITED,
	BRIDGE_RESET_HANDSHAKE,
	BRIDGE_RESET_SYNCED,
	BRIDGE_ENUM_GPIO_COMPLETE,
	BRIDGE_ENUM_I2C_COMPLETE,
	BRIDGE_ENUM_SPI_COMPLETE,
	BRIDGE_SUSPEND,
	BRIDGE_STARTED,
	BRIDGE_FAILED,
};

struct usbio_dev {
	struct usb_device *udev;
	struct usb_interface *intf;
	u8 ep0; /* the address of the control endpoint */
	u8 in_ep; /* the address of the bulk in endpoint */
	u8 out_ep; /* the address of the bulk out endpoint */

	/* control buffer for xfer */
	u16 cbuf_len;
	unsigned char *cbuf;

	/* the urb/buffer for read */
	u16 ibuf_len;
	struct urb *in_urb;
	unsigned char *ibuf;

	enum bridge_state state;

	struct list_head stubs_list;

	/* to wait for an ongoing write ack */
	wait_queue_head_t ack_wq;

	struct mfd_cell *cells;
	int cell_count;
	struct mutex mutex;
};

#endif
