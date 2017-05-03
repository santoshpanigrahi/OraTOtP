WHENEVER SQLERROR EXIT SQL.SQLCODE

SET DEFINE ON

ALTER SESSION SET CURRENT_SCHEMA=&_vUsername
/

SET DEFINE OFF

CREATE OR REPLACE PACKAGE TWOFACTOR_ADMIN AS
  /************************************************************************

      OraTOtP - Oracle Time-based One-time Password
      Copyright (C) 2016  Rodrigo Jorge <http://www.dbarj.com.br/>

      This program is free software: you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published by
      the Free Software Foundation, either version 3 of the License, or
      (at your option) any later version.

      This program is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
      GNU General Public License for more details.

      You should have received a copy of the GNU General Public License
      along with this program.  If not, see <http://www.gnu.org/licenses/>.

  ************************************************************************/
  PROCEDURE SETUP(PUSER IN VARCHAR2, PPASS IN VARCHAR2 DEFAULT NULL, PGAP IN NUMBER DEFAULT NULL);
  PROCEDURE DECONFIG(PUSER IN VARCHAR2, PCODE IN VARCHAR2 DEFAULT NULL, PPASS IN VARCHAR2 DEFAULT NULL, PISADMIN IN BOOLEAN DEFAULT TRUE);
  PROCEDURE VALIDATE(PUSER IN VARCHAR2, PCODE IN VARCHAR2, PPASS IN VARCHAR2 DEFAULT NULL);
  PROCEDURE FORGET(PUSER IN VARCHAR2);
  -- Can't run to another user:
  PROCEDURE AUTHENTICATE(PCODE IN VARCHAR2, PPASS IN VARCHAR2 DEFAULT NULL);
  PROCEDURE REMEMBER(PCODE IN VARCHAR2, PPASS IN VARCHAR2 DEFAULT NULL, PINT IN INTERVAL DAY TO SECOND DEFAULT NULL);
END TWOFACTOR_ADMIN;
/

CREATE OR REPLACE PACKAGE BODY TWOFACTOR_ADMIN AS
  /************************************************************************

      OraTOtP - Oracle Time-based One-time Password
      Copyright (C) 2016  Rodrigo Jorge <http://www.dbarj.com.br/>

      This program is free software: you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published by
      the Free Software Foundation, either version 3 of the License, or
      (at your option) any later version.

      This program is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
      GNU General Public License for more details.

      You should have received a copy of the GNU General Public License
      along with this program.  If not, see <http://www.gnu.org/licenses/>.

  ************************************************************************/
  PROCEDURE ERRORIFUSERNOTSETUP(PUSER IN VARCHAR2) IS
  BEGIN
    IF TWOFACTOR_INTERNAL.ISUSERSETUP(PUSER) = FALSE
    THEN
      RAISE_APPLICATION_ERROR(-20000, 'Setup the user first.');
    END IF;
  END;

  PROCEDURE ERRORIFUSERNOTAUTH(PUSER IN VARCHAR2) IS
  BEGIN
    ERRORIFUSERNOTSETUP(PUSER);
    IF NOT TWOFACTOR_INTERNAL.ISUSERVALIDATED(PUSER)
    THEN
      RAISE_APPLICATION_ERROR(-20000, '2Factor not validated yet.');
    ELSIF NOT TWOFACTOR_INTERNAL.ISUSERENABLED(PUSER)
    THEN
      RAISE_APPLICATION_ERROR(-20000, 'User is disabled from using 2Factor.');
    ELSIF SYS_CONTEXT('TWOFACTOR_CTX', 'AUTHENTICATED') <> 'TRUE'
    THEN
      RAISE_APPLICATION_ERROR(-20000, 'Authenticate first.');
    END IF;
  END;

  PROCEDURE SETUP(PUSER IN VARCHAR2, PPASS IN VARCHAR2 DEFAULT NULL, PGAP IN NUMBER DEFAULT NULL) IS
  BEGIN
    IF NOT TWOFACTOR_INTERNAL.ISUSERSETUP(PUSER)
    THEN
      TWOFACTOR_INTERNAL.ADDUSER(PUSER, PGAP, PPASS);
      DBMS_OUTPUT.PUT_LINE(TWOFACTOR_INTERNAL.URLGEN(PUSER, PPASS));
    ELSE
      RAISE_APPLICATION_ERROR(-20000, 'User already configured. Deconfig it to setup again.');
    END IF;
  END;

  PROCEDURE DECONFIG(PUSER IN VARCHAR2, PCODE IN VARCHAR2 DEFAULT NULL, PPASS IN VARCHAR2 DEFAULT NULL, PISADMIN IN BOOLEAN DEFAULT TRUE) IS
  BEGIN
    ERRORIFUSERNOTSETUP(PUSER);
    IF PISADMIN
    THEN
      TWOFACTOR_INTERNAL.REMUSER(PUSER);
    ELSE
      -- Only allow deconfig without code if not validated yet
      IF NOT TWOFACTOR_INTERNAL.ISUSERVALIDATED(PUSER)
      THEN
        TWOFACTOR_INTERNAL.REMUSER(PUSER);
      ELSIF PCODE IS NULL
      THEN
        RAISE_APPLICATION_ERROR(-20000, 'You need to type a code or ask an admin to Deconfig it.');
      ELSIF TWOFACTOR_INTERNAL.CODECHECK(PUSER, PCODE, PPASS)
      THEN
        TWOFACTOR_INTERNAL.REMUSER(PUSER);
      ELSE
        RAISE_APPLICATION_ERROR(-20000, 'Code not valid.');
      END IF;
    END IF;
  END;

  PROCEDURE VALIDATE(PUSER IN VARCHAR2, PCODE IN VARCHAR2, PPASS IN VARCHAR2 DEFAULT NULL) IS
  BEGIN
    ERRORIFUSERNOTSETUP(PUSER);
    -- First time Validation to enable and allow usage of 2Factor
    IF TWOFACTOR_INTERNAL.ISUSERVALIDATED(PUSER)
    THEN
      RAISE_APPLICATION_ERROR(-20000, 'User already validated.');
    END IF;
    IF TWOFACTOR_INTERNAL.CODECHECK(PUSER, PCODE, PPASS)
    THEN
      TWOFACTOR_INTERNAL.SETVALIDATED(PUSER);
      TWOFACTOR_INTERNAL.SETSTATUS(PUSER, 'ENABLED');
    ELSE
      RAISE_APPLICATION_ERROR(-20000, 'Code not valid.');
    END IF;
  END;

  PROCEDURE AUTHENTICATE(PCODE IN VARCHAR2, PPASS IN VARCHAR2 DEFAULT NULL) IS
    VUSER CONSTANT VARCHAR2(30 CHAR) := SYS_CONTEXT('USERENV', 'SESSION_USER');
  BEGIN
    ERRORIFUSERNOTSETUP(VUSER);
    -- Daily Validation
    IF NOT TWOFACTOR_INTERNAL.ISUSERVALIDATED(VUSER)
    THEN
      RAISE_APPLICATION_ERROR(-20000, '2Factor not validated yet.');
    ELSIF NOT TWOFACTOR_INTERNAL.ISUSERENABLED(VUSER)
    THEN
      RAISE_APPLICATION_ERROR(-20000, 'User is disabled from using 2Factor.');
    ELSIF TWOFACTOR_INTERNAL.CODECHECK(VUSER, PCODE, PPASS)
    THEN
      TWOFACTOR_INTERNAL.SETAUTHENTICATED;
    ELSE
      RAISE_APPLICATION_ERROR(-20000, 'Code not valid.');
    END IF;
  END;

  PROCEDURE REMEMBER(PCODE IN VARCHAR2, PPASS IN VARCHAR2 DEFAULT NULL, PINT IN INTERVAL DAY TO SECOND DEFAULT NULL) IS
    VUSER CONSTANT VARCHAR2(30 CHAR) := SYS_CONTEXT('USERENV', 'SESSION_USER');
  BEGIN
    ERRORIFUSERNOTAUTH(VUSER);
    IF TWOFACTOR_INTERNAL.CODECHECK(VUSER, PCODE, PPASS)
    THEN
      IF NOT TWOFACTOR_INTERNAL.ADDMEMORY(VUSER, PINT)
      THEN
        RAISE_APPLICATION_ERROR(-20000, 'Max trusted locations exceeded. Clean first.');
      END IF;
    ELSE
      RAISE_APPLICATION_ERROR(-20000, 'Code not valid.');
    END IF;
  END;

  PROCEDURE FORGET(PUSER IN VARCHAR2) AS
  BEGIN
    ERRORIFUSERNOTAUTH(PUSER);
    TWOFACTOR_INTERNAL.CLEANMEMORY(PUSER);
  END;

END TWOFACTOR_ADMIN;
/
