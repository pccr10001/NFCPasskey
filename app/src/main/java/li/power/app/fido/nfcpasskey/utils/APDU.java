package li.power.app.fido.nfcpasskey.utils;

public class APDU {

    public static byte[] SELECT_APPLET = {0x00, (byte) 0xA4, 0x04, 0x00};
    public static byte[] FIDO_APPLET_AID = {(byte) 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01};

    public static byte[] selectFidoAppletCmd() {
        return selectAppletCmd(FIDO_APPLET_AID);
    }

    public static byte[] selectAppletCmd(byte[] aid) {
        byte[] cmd = new byte[SELECT_APPLET.length + aid.length + 1];
        System.arraycopy(SELECT_APPLET, 0, cmd, 0, SELECT_APPLET.length);
        System.arraycopy(aid, 0, cmd, SELECT_APPLET.length + 1, aid.length);
        cmd[SELECT_APPLET.length] = (byte) aid.length;
        return cmd;
    }


}

