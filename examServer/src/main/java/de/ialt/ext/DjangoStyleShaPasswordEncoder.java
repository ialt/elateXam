package de.ialt.ext;

import org.acegisecurity.providers.encoding.ShaPasswordEncoder;

/**
 * DjangoStyleShaPasswordEncoder merges and demerges salted passwords,
 * django style.
 * Details: http://github.com/jacobian/django/blob/master/django/contrib/auth/models.py#L36
 * While the default Acegi-style merge takes the form password{salt},
 * django simply concatenates the two: salt + password.
 *
 * The mergePasswordAndSalt and demergePasswordAndSalt methods are overriden
 * with respect to org.acegisecurity.providers.encoding.BasePasswordEncoder.
 *
 * Additional machinery to get this to work is a User, resp. UserDetails
 * instance, on which a property specified in the security.xml can be invoked;
 * here and now, this property is getPasswordSalt.
 *
 * Here, a user in users.xml, who has no salt, won't reach this methods, thus
 * salted and unsalted SHA1 passwords can live safely side by side in users.xml.
 *
 * To specify a salt in users.xml, use the password_salt attribute.
 *
 *
 * @author Martin Czygan
 */
public class DjangoStyleShaPasswordEncoder extends ShaPasswordEncoder {

    @Override
    protected String[] demergePasswordAndSalt(String mergedPasswordSalt) {

        if ((mergedPasswordSalt == null) || "".equals(mergedPasswordSalt)) {
            throw new IllegalArgumentException("Cannot pass a null or empty String");
        }

        String password = mergedPasswordSalt.substring(5);
        String salt = mergedPasswordSalt.substring(0, 5);
        
        // String salt = "";
        // int saltBegins = mergedPasswordSalt.lastIndexOf("{");
        // if ((saltBegins != -1) && ((saltBegins + 1) < mergedPasswordSalt.length())) {
        //    salt = mergedPasswordSalt.substring(saltBegins + 1, mergedPasswordSalt.length() - 1);
        //    password = mergedPasswordSalt.substring(0, saltBegins);
        // }

        return new String[]{password, salt};
    }

    @Override
    protected String mergePasswordAndSalt(String password, Object salt, boolean strict) {

        if (password == null) {
            password = "";
        }

        // if (strict && (salt != null)) {
        //    if ((salt.toString().lastIndexOf("{") != -1) || (salt.toString().lastIndexOf("}") != -1)) {
        //        throw new IllegalArgumentException("Cannot use { or } in salt.toString()");
        //    }
        //}

        if ((salt == null) || "".equals(salt)) {
            return password;
        } else {
            // return password + "{" + salt.toString() + "}";
            return salt.toString() + password;
        }
    }
}
