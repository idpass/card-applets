package org.idpass.offcard.misc;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.annotation.ElementType;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface IdpassConfig
{
    String appletInstanceAID();
    byte[] privileges();
    byte[] installParams();
}
