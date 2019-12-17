package org.idpass.build;

import apdu4j.APDUBIBO;
import apdu4j.CommandAPDU;
import apdu4j.ResponseAPDU;
import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.logging.Logger;
import org.gradle.api.tasks.TaskAction;

import javax.smartcardio.CardException;
import java.io.IOException;
import java.util.Arrays;

import static pro.javacard.gp.GPException.check;

public class PingTask extends DefaultTask {
  private final Logger logger;
  private APDUBIBO channel;
  private Card card;

  public PingTask() {
    logger = getLogger();
  }

  @TaskAction
  public void ping() {
    card = new Card();
    try {
      card.open();
    } catch (CardException e) {
      throw new GradleException("Error opening card", e);
    }

    channel = card.getChannel();

    try {
      logger.info("Selecting the applet");
      select();
      logger.info("Ping");
      do_ping();
      logger.info("Success");
    } catch (IOException e) {
      throw new GradleException("I/O error", e);
    } finally {
      card.close();
    }
  }

  private void select() throws IOException {
    card.select(Identifiers.AUTH_AID);
  }

  private void do_ping() throws IOException {
    CommandAPDU cmd = new CommandAPDU(0x00, 0x1B, 0x00, 0x00, new byte[0]);
    ResponseAPDU result = check(channel.transmit(cmd));
    if (!Arrays.equals(result.getData(), "hello world".getBytes())) {
      throw new IOException("did not get hello world");
    }
  }
}
