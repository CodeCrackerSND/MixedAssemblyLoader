//using Marina;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Marina
{
public partial class PEBinary
{
    #region Write Helpers

    private static void WriteInt16(byte[] buf, int idx, short v)
    {
        var b = BitConverter.GetBytes(v);
        Buffer.BlockCopy(b, 0, buf, idx, 2);
    }
    private static void WriteInt32(byte[] buf, int idx, int v)
    {
        var b = BitConverter.GetBytes(v);
        Buffer.BlockCopy(b, 0, buf, idx, 4);
    }
    private static void WriteInt64(byte[] buf, int idx, long v)
    {
        var b = BitConverter.GetBytes(v);
        Buffer.BlockCopy(b, 0, buf, idx, 8);
    }
    private static void WriteUInt32(byte[] buf, int idx, uint v)
    {
        var b = BitConverter.GetBytes(v);
        Buffer.BlockCopy(b, 0, buf, idx, 4);
    }
    private static void WriteUInt64(byte[] buf, int idx, ulong v)
    {
        var b = BitConverter.GetBytes(v);
        Buffer.BlockCopy(b, 0, buf, idx, 8);
    }

    #endregion
}

}
