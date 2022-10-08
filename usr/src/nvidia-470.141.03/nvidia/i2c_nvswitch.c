/*******************************************************************************
    Copyright (c) 2021 NVIDIA Corporation

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to
    deal in the Software without restriction, including without limitation the
    rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
    sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be
        included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.

*******************************************************************************/

#include "linux_nvswitch.h"
#include <linux/i2c.h>

#if defined(CONFIG_I2C) || defined(CONFIG_I2C_MODULE)

#define NVSWITCH_I2C_GET_PARENT(adapter) \
            (NVSWITCH_DEV *)pci_get_drvdata(to_pci_dev((adapter)->dev.parent));

#define NVSWITCH_I2C_GET_ALGO_DATA(adapter) \
            (nvswitch_i2c_algo_data *)(adapter)->algo_data;

typedef struct
{
    NvU32 port;
} nvswitch_i2c_algo_data;

static int
nvswitch_i2c_algo_master_xfer
(
    struct i2c_adapter *adap,
    struct i2c_msg msgs[],
    int num
)
{
    int rc;
    int i;
    NvU32 port;
    NvlStatus status = NVL_SUCCESS;
    nvswitch_i2c_algo_data *i2c_algo_data;
    NVSWITCH_DEV *nvswitch_dev;
    const unsigned int supported_i2c_flags = I2C_M_RD
#if defined (I2C_M_DMA_SAFE)
    | I2C_M_DMA_SAFE
#endif
    ;

    nvswitch_dev = NVSWITCH_I2C_GET_PARENT(adap);
    if (nvswitch_dev == NULL)
    {
        return -ENODEV;
    }

    rc = mutex_lock_interruptible(&nvswitch_dev->device_mutex);
    if (rc)
    {
        return rc;
    }

    if (nvswitch_dev->unusable)
    {
        printk(KERN_INFO "%s: a stale fd detected\n", nvswitch_dev->name);
        status = NVL_ERR_INVALID_STATE;
        goto nvswitch_i2c_algo_master_xfer_exit;
    }

    i2c_algo_data = NVSWITCH_I2C_GET_ALGO_DATA(adap);
    if (i2c_algo_data == NULL)
    {
        status = NVL_ERR_INVALID_STATE;
        goto nvswitch_i2c_algo_master_xfer_exit;
    }

    port = i2c_algo_data->port;

    for (i = 0; (i < num) && (status == NVL_SUCCESS); i++)
    {
        if (msgs[i].flags & ~supported_i2c_flags)
        {
            status = NVL_ERR_NOT_SUPPORTED;
        }
        else
        {
            status = nvswitch_lib_i2c_transfer(nvswitch_dev->lib_device, port,
                                               (msgs[i].flags & I2C_M_RD) ?
                                                   NVSWITCH_I2C_CMD_READ : NVSWITCH_I2C_CMD_WRITE,
                                               (NvU8)(msgs[i].addr & 0x7f),
                                               (NvU8)(msgs[i].buf[0]),
                                               (NvU32)(msgs[i].len & 0xffffUL),
                                               (NvU8 *)msgs[i].buf);
        }
    }

nvswitch_i2c_algo_master_xfer_exit:
    mutex_unlock(&nvswitch_dev->device_mutex);

    rc = nvswitch_map_status(status);
    return (rc == 0) ? num : rc;
}

static int
nvswitch_i2c_algo_smbus_xfer
(
    struct i2c_adapter *adap,
    u16 addr,
    unsigned short flags,
    char read_write,
    u8 command,
    int protocol,
    union i2c_smbus_data *data
)
{
    int rc = -EIO;
    NvU32 port;
    NvU8 cmd;
    NvU32 len;
    NvU8 type;
    NvU8 *xfer_data;
    NvlStatus status = NVL_SUCCESS;
    nvswitch_i2c_algo_data *i2c_algo_data;
    NVSWITCH_DEV *nvswitch_dev;

    nvswitch_dev = NVSWITCH_I2C_GET_PARENT(adap);
    if (nvswitch_dev == NULL)
    {
        return -ENODEV;
    }

    rc = mutex_lock_interruptible(&nvswitch_dev->device_mutex);
    if (rc)
    {
        return rc;
    }

    if (nvswitch_dev->unusable)
    {
        printk(KERN_INFO "%s: a stale fd detected\n", nvswitch_dev->name);
        status = NVL_ERR_INVALID_STATE;
        goto nvswitch_i2c_algo_smbus_xfer_exit;
    }

    i2c_algo_data = NVSWITCH_I2C_GET_ALGO_DATA(adap);
    if (i2c_algo_data == NULL)
    {
        status = NVL_ERR_INVALID_STATE;
        goto nvswitch_i2c_algo_smbus_xfer_exit;
    }

    port = i2c_algo_data->port;

    switch (protocol)
    {
        case I2C_SMBUS_QUICK:
        {
            cmd = 0;
            len = 0;
            type = (read_write == I2C_SMBUS_READ) ?
                       NVSWITCH_I2C_CMD_SMBUS_QUICK_READ :
                       NVSWITCH_I2C_CMD_SMBUS_QUICK_WRITE;
            xfer_data = NULL;
            break;
        }
        case I2C_SMBUS_BYTE:
        {
            cmd = 0;
            len = 1;

            if (read_write == I2C_SMBUS_READ)
            {
                type = NVSWITCH_I2C_CMD_READ;
                xfer_data = (NvU8 *)&data->byte;
            }
            else
            {
                type = NVSWITCH_I2C_CMD_WRITE;
                xfer_data = &command;
            }
            break;
        }
        case I2C_SMBUS_BYTE_DATA:
        {
            cmd = (NvU8)command;
            len = 1;
            type = (read_write == I2C_SMBUS_READ) ?
                       NVSWITCH_I2C_CMD_SMBUS_READ :
                       NVSWITCH_I2C_CMD_SMBUS_WRITE;
            cmd = (NvU8)command;
            xfer_data = (NvU8 *)&data->byte;
            break;
        }
        case I2C_SMBUS_WORD_DATA:
        {
            cmd = (NvU8)command;
            len = 2;
            type = (read_write == I2C_SMBUS_READ) ?
                       NVSWITCH_I2C_CMD_SMBUS_READ :
                       NVSWITCH_I2C_CMD_SMBUS_WRITE;
            xfer_data = (NvU8 *)&data->word;
            break;
        }
        default:
        {
            status = NVL_BAD_ARGS;
            goto nvswitch_i2c_algo_smbus_xfer_exit;
        }
    }

    status = nvswitch_lib_i2c_transfer(nvswitch_dev->lib_device, port,
                                       type, (NvU8)(addr & 0x7f),
                                       cmd, len, (NvU8 *)xfer_data);

nvswitch_i2c_algo_smbus_xfer_exit:
    mutex_unlock(&nvswitch_dev->device_mutex);

    return nvswitch_map_status(status);
}

static u32 nvswitch_i2c_algo_functionality(struct i2c_adapter *adap)
{
    return (I2C_FUNC_I2C             |
            I2C_FUNC_SMBUS_QUICK     |
            I2C_FUNC_SMBUS_BYTE      |
            I2C_FUNC_SMBUS_BYTE_DATA |
            I2C_FUNC_SMBUS_WORD_DATA);
}

static struct i2c_algorithm nvswitch_i2c_algo = {
    .master_xfer      = nvswitch_i2c_algo_master_xfer,
    .smbus_xfer       = nvswitch_i2c_algo_smbus_xfer,
    .functionality    = nvswitch_i2c_algo_functionality,
};

struct i2c_adapter nvswitch_i2c_adapter_prototype = {
    .owner             = THIS_MODULE,
    .algo              = &nvswitch_i2c_algo,
    .algo_data         = NULL,
};

struct i2c_adapter *
nvswitch_i2c_add_adapter
(
    NVSWITCH_DEV *nvswitch_dev,
    NvU32 port
)
{
    struct i2c_adapter *adap = NULL;
    int rc = 0;
    struct pci_dev *pci_dev;
    nvswitch_i2c_algo_data *i2c_algo_data = NULL;

    if (nvswitch_dev == NULL)
    {
        printk(KERN_ERR "nvswitch_dev is NULL!\n");
        return NULL;
    }

    adap = nvswitch_os_malloc(sizeof(struct i2c_adapter));
    if (adap == NULL)
    {
        return NULL;
    }

    nvswitch_os_memcpy(adap,
                       &nvswitch_i2c_adapter_prototype,
                       sizeof(struct i2c_adapter));

    i2c_algo_data = nvswitch_os_malloc(sizeof(nvswitch_i2c_algo_data));
    if (i2c_algo_data == NULL)
    {
        goto cleanup;
    }

    i2c_algo_data->port = port;
    pci_dev = nvswitch_dev->pci_dev;
    adap->dev.parent = &pci_dev->dev;
    adap->algo_data = (void *)i2c_algo_data;

    rc = nvswitch_os_snprintf(adap->name,
                              sizeof(adap->name),
                              "NVIDIA NVSwitch i2c adapter %u at %x:%02x.%u",
                              port,
                              NV_PCI_BUS_NUMBER(pci_dev),
                              NV_PCI_SLOT_NUMBER(pci_dev),
                              PCI_FUNC(pci_dev->devfn));
    if ((rc < 0) && (rc >= sizeof(adap->name)))
    {
        goto cleanup;
    }

    rc = i2c_add_adapter(adap);
    if (rc < 0)
    {
        goto cleanup;
    }

    return adap;

cleanup:
    nvswitch_os_free(i2c_algo_data);
    nvswitch_os_free(adap);

    return NULL;
}

void
nvswitch_i2c_del_adapter
(
    struct i2c_adapter *adap
)
{
    if (adap != NULL)
    {
        nvswitch_os_free(adap->algo_data);
        i2c_del_adapter(adap);
        nvswitch_os_free(adap);
    }
}

#else // (defined(CONFIG_I2C) || defined(CONFIG_I2C_MODULE))

struct i2c_adapter *
nvswitch_i2c_add_adapter
(
    NVSWITCH_DEV *nvswitch_dev,
    NvU32 port
)
{
    return NULL;
}

void
nvswitch_i2c_del_adapter
(
    struct i2c_adapter *adap
)
{
}

#endif // (defined(CONFIG_I2C) || defined(CONFIG_I2C_MODULE))
