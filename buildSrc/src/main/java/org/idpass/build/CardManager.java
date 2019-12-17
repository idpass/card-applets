package org.idpass.build;

import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.logging.Logger;
import org.gradle.api.tasks.TaskAction;
import pro.javacard.CAPFile;

import javax.smartcardio.CardException;
import java.io.FileInputStream;
import java.io.IOException;

public class CardManager extends DefaultTask
{
    private final Logger logger;
    private Card card;
    private Action action = Action.UNDEFINED;

    public static enum Action { INSTALL, UNINSTALL, UNDEFINED }

    public CardManager()
    {
        logger = getLogger();
    }

    public void setAction(Action x)
    {
        this.action = x;
    }

    @TaskAction public void doAction()
    {
        try {
            openCard();
            card.openSecureChannel();
            CAPFile capFile = loadCap(logger);
            switch (action) {
            case INSTALL:
                logger.info("Install");
                card.install(capFile);
                logger.info("Success");
                break;
            case UNINSTALL:
                logger.info("UnInstall");
                card.uninstall(capFile);
                logger.info("Success");
                break;
            default:
                break;
            }
        } catch (IOException e) {
            throw new GradleException("I/O error", e);
        } finally {
            card.close();
            card = null;
        }
    }

    private void openCard()
    {
        if (card != null) {
            throw new GradleException("leaked card handle");
        }
        card = new Card();
        try {
            card.open();
            logger.info("Opening a SecureChannel");
        } catch (CardException e) {
            throw new GradleException("Error opening card", e);
        }
    }

    private CAPFile loadCap(Logger logger) throws IOException
    {
        logger.info("Loading cap file");
        FileInputStream in = new FileInputStream(
            "build/javacard/org/idpass/auth/javacard/auth.cap");
        // FileInputStream in = new
        // FileInputStream("build/javacard/org/idpass/tools/javacard/tools.cap");
        CAPFile capFile = CAPFile.fromStream(in);
        in.close();
        return capFile;
    }
}
