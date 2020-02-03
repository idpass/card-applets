package org.idpass.offcard.misc;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.annotation.ElementType;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface IdpassConfig {
    String packageAID() default "";
    String appletAID() default "";
    String instanceAID() default "";
    String capFile() default "";
    byte[] privileges();
    byte[] installParams();
    Class<?> api() default Void.class;
}
