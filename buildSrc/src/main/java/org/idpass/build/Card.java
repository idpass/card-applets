package org.idpass.build;

import apdu4j.APDUBIBO;
import apdu4j.CardChannelBIBO;
import apdu4j.CommandAPDU;
import apdu4j.HexUtils;
import apdu4j.TerminalManager;
import pro.javacard.AID;
import pro.javacard.CAPFile;
import pro.javacard.gp.GPCardKeys;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPRegistryEntry;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.ISO7816;
import pro.javacard.gp.PlaintextKeys;
import pro.javacard.gp.SecureChannelParameters;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.io.ByteArrayOutputStream;

import static pro.javacard.gp.GPException.check;

public class Card {
    private static boolean DEBUG = true;
    private javax.smartcardio.Card card;
    private APDUBIBO channel;
    private GPSession gp;

    public Card() {
    }

    public APDUBIBO getChannel() {
        return channel;
    }

    public javax.smartcardio.Card getCard() {
        return card;
    }

    public void open() throws CardException {
        // Now actually talk to possible terminals
        try {
            final TerminalFactory tf;

            tf = TerminalManager.getTerminalFactory(null);

            CardTerminals terminals = tf.terminals();

            // List terminals if needed
            if (DEBUG) {
                System.out.println("# Detected readers from " + tf.getProvider().getName());
                for (CardTerminal term : terminals.list()) {
                    String c = " ";
                    if (term.isCardPresent()) {
                        c = "*";
                    }
                    System.out.println("[" + c + "] " + term.getName());
                }
            }

            // Select terminal(s) to work on
            List<CardTerminal> readers = terminals.list(CardTerminals.State.CARD_PRESENT);

            if (readers.size() == 0) {
                throw new RuntimeException("No smart card readers with a card found");
            }
            if (readers.size() > 1) {
                throw new RuntimeException("More than one reader with a card found");
            }
            CardTerminal reader = readers.get(0);
            card = null;
            try {
                // Establish connection
                card = reader.connect("*");
                // We use apdu4j which by default uses jnasmartcardio
                // which uses real SCardBeginTransaction
                card.beginExclusive();
                channel = CardChannelBIBO.getBIBO(card.getBasicChannel());

                if (DEBUG) {
                    System.out.println("Reader: " + reader.getName());
                    System.out.println("ATR: " + HexUtils.bin2hex(card.getATR().getBytes()));
                    System.out.println("More information about your card:");
                    System.out.println("    http://smartcard-atr.appspot.com/parse?ATR=" + HexUtils.bin2hex(card.getATR().getBytes()));
                    System.out.println();
                }

            } catch (GPException e) {
                throw e;
            }
        } catch (CardException e) {
            // Sensible wrapper for the different PC/SC exceptions
            if (TerminalManager.getExceptionMessage(e) != null) {
                System.out.println("PC/SC failure: " + TerminalManager.getExceptionMessage(e));
            }
            throw e;
        } catch (NoSuchAlgorithmException e) {
            throw new CardException("No such algorithm exception");
        }
    }

    public void openSecureChannel() throws IOException {
        // Normally assume a single master key
        PlaintextKeys keys;
        if (System.getenv("CARD_KEY") != null) {
            byte[] k = HexUtils.stringToBin(System.getenv("CARD_KEY"));
            byte[] kcv = null;
            keys = PlaintextKeys.fromMasterKey(k, kcv);
        } else {
            Optional<SecureChannelParameters> params = SecureChannelParameters.fromEnvironment();
            // XXX: better checks for exclusive key options
            if (params.isPresent()) {
                keys = (PlaintextKeys) params.get().getCardKeys();
            } else {
                System.out.println("Warning: no keys given, using default test key");
                keys = PlaintextKeys.defaultKey();
            }
        }

        // Authenticate, only if needed
        EnumSet<GPSession.APDUMode> mode = GPSession.defaultMode.clone();

        gp = GPSession.discover(channel);

        // IMPORTANT PLACE. Possibly brick the card now, if keys don't match.
        gp.openSecureChannel(keys, null, null, mode);


//        // --uninstall <cap>
//        if (args.has(OPT_UNINSTALL)) {
//            List<CAPFile> caps = getCapFileList(args, OPT_UNINSTALL);
//            for (CAPFile instcap : caps) {
//                AID aid = instcap.getPackageAID();
//                if (!gp.getRegistry().allAIDs().contains(aid)) {
//                    System.out.println(aid + " is not present on card!");
//                } else {
//                    gp.deleteAID(aid, true);
//                    System.out.println(aid + " deleted.");
//                }
//            }
//        }
//
//        // --install <applet.cap> (--applet <aid> --create <aid> --privs <privs> --params <params>)
//        if (args.has(OPT_INSTALL)) {
//            final File capfile;
//            capfile = (File) args.valueOf(OPT_INSTALL);
//
//            final CAPFile instcap;
//            try (FileInputStream fin = new FileInputStream(capfile)) {
//                instcap = CAPFile.fromStream(fin);
//            }
//
//            if (args.has(OPT_VERBOSE)) {
//                instcap.dump(System.out);
//            }
//
//            GPRegistry reg = gp.getRegistry();
//
//            // Remove existing load file
//            if (args.has(OPT_FORCE) && reg.allPackageAIDs().contains(instcap.getPackageAID())) {
//                gp.deleteAID(instcap.getPackageAID(), true);
//            }
//
//            // Load
//            if (instcap.getAppletAIDs().size() <= 1) {
//                calculateDapPropertiesAndLoadCap(args, gp, instcap);
//            }
//
//            // Install
//            final AID appaid;
//            final AID instanceaid;
//            if (instcap.getAppletAIDs().size() == 0) {
//                return;
//            } else if (instcap.getAppletAIDs().size() > 1) {
//                if (args.has(OPT_APPLET)) {
//                    appaid = AID.fromString(args.valueOf(OPT_APPLET));
//                } else {
//                    fail("CAP contains more than one applet, specify the right one with --" + OPT_APPLET);
//                    return;
//                }
//            } else {
//                appaid = instcap.getAppletAIDs().get(0);
//            }
//
//            // override
//            if (args.has(OPT_CREATE)) {
//                instanceaid = AID.fromString(args.valueOf(OPT_CREATE));
//            } else {
//                instanceaid = appaid;
//            }
//
//            GPRegistryEntry.Privileges privs = getInstPrivs(args);
//
//            // Remove existing default app
//            if (args.has(OPT_FORCE) && (reg.getDefaultSelectedAID().isPresent() && privs.has(GPRegistryEntry.Privilege.CardReset))) {
//                gp.deleteAID(reg.getDefaultSelectedAID().get(), false);
//            }
//
//            // warn
//            if (gp.getRegistry().allAppletAIDs().contains(instanceaid)) {
//                System.err.println("WARNING: Applet " + instanceaid + " already present on card");
//            }
//
//            // shoot
//            gp.installAndMakeSelectable(instcap.getPackageAID(), appaid, instanceaid, privs, getInstParams(args));
//        }
//
//        // --create <aid> (--applet <aid> --package <aid> or --cap <cap>)
//        if (args.has(OPT_CREATE) && !args.has(OPT_INSTALL)) {
//            AID packageAID = null;
//            AID appletAID = null;
//
//            // Load AID-s from cap if present
//            if (cap != null) {
//                packageAID = cap.getPackageAID();
//                if (cap.getAppletAIDs().size() != 1) {
//                    throw new IllegalArgumentException("There should be only one applet in CAP. Use --" + OPT_APPLET + " instead.");
//                }
//                appletAID = cap.getAppletAIDs().get(0);
//            }
//
//            // override
//            if (args.has(OPT_PACKAGE)) {
//                packageAID = AID.fromString(args.valueOf(OPT_PACKAGE));
//            }
//            if (args.has(OPT_APPLET)) {
//                appletAID = AID.fromString(args.valueOf(OPT_APPLET));
//            }
//
//            // check
//            if (packageAID == null || appletAID == null)
//                throw new IllegalArgumentException("Need --" + OPT_PACKAGE + " and --" + OPT_APPLET + " or --" + OPT_CAP);
//
//            // warn
//            if (gp.getRegistry().allAIDs().contains(appletAID)) {
//                System.err.println("WARNING: Applet " + appletAID + " already present on card");
//            }
//
//            // shoot
//            AID instanceAID = AID.fromString(args.valueOf(OPT_CREATE));
//            gp.installAndMakeSelectable(packageAID, appletAID, instanceAID, getInstPrivs(args), getInstParams(args));
//        }
//
    }

    public void close() {
        if (card != null) {
            try {
                card.endExclusive();
                card.disconnect(true);
            } catch (CardException e) {
                throw new RuntimeException("failed to close card");
            }
        }
    }

    public void select(byte[] aid) throws IOException {
        check(channel.transmit(new CommandAPDU(0x00, ISO7816.INS_SELECT, 0x04, 0x00, aid)));
    }

    public void uninstall(CAPFile capFile) throws IOException {
        AID aid = capFile.getPackageAID();
        if (!gp.getRegistry().allAIDs().contains(aid)) {
            System.out.println(aid + " is not present on card!");
        } else {
            gp.deleteAID(aid, true);
            System.out.println(aid + " deleted.");
        }
    }

    public void install(CAPFile cap) throws IOException {
        loadCap(cap);
        do_install(cap);
    }

    private void do_install(CAPFile cap) throws IOException {
        final AID appaid;
        final AID appaid_withversion;
        byte[] insparam;
        if (cap.getAppletAIDs().size() == 0) {
            throw new IllegalArgumentException("no applets");
        } else if (cap.getAppletAIDs().size() > 1) {
            throw new IllegalArgumentException("more than one applet");
        } else {
            appaid = cap.getAppletAIDs().get(0);
            
            byte[] appletversion = new byte[]{(byte)0x01};
            insparam = new byte[]{(byte)0xC9,(byte)0x03,(byte)0x01,(byte)0x9C}; // 03019C

            ByteArrayOutputStream arr = new ByteArrayOutputStream();
            arr.write(appaid.getBytes());
            arr.write(appletversion);
            appaid_withversion = new AID(arr.toByteArray());
        }
        //gp.installAndMakeSelectable(cap.getPackageAID(), appaid, appaid, new GPRegistryEntry.Privileges(), new byte[0]);
        gp.installAndMakeSelectable(cap.getPackageAID(), appaid, appaid_withversion, new GPRegistryEntry.Privileges(), new byte[0]);
    }

    private void loadCap(CAPFile cap) throws IOException {
        try {
            gp.loadCapFile(cap, null, "SHA-1");
            System.out.println("CAP loaded");
        } catch (GPException e) {
            switch (e.sw) {
                case 0x6A80:
                    System.err.println("Applet loading failed. Are you sure the card can handle it?");
                    break;
                case 0x6985:
                    System.err.println("Applet loading not allowed. Are you sure the domain can accept it?");
                    break;
                default:
                    // Do nothing. Here for findbugs
            }
            throw e;
        }
    }
}
