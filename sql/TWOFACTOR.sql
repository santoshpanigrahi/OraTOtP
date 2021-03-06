WHENEVER SQLERROR EXIT SQL.SQLCODE

SET DEFINE ON

ALTER SESSION SET CURRENT_SCHEMA=&_vUsername
/

SET DEFINE OFF

CREATE OR REPLACE PACKAGE TWOFACTOR AS
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
  PROCEDURE SETUP;
  PROCEDURE DECONFIG(PCODE IN VARCHAR2 DEFAULT NULL);
  PROCEDURE VALIDATE(PCODE IN VARCHAR2);
  PROCEDURE AUTHENTICATE(PCODE IN VARCHAR2);
  PROCEDURE REMEMBER(PCODE IN VARCHAR2);
  PROCEDURE FORGET;
  PROCEDURE SETSECRETPASS(PPASS IN VARCHAR2);
END TWOFACTOR;
/

CREATE OR REPLACE PACKAGE BODY TWOFACTOR AS
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
  VUSER CONSTANT VARCHAR2(30) := SYS_CONTEXT('USERENV', 'SESSION_USER');
  VPASS VARCHAR2(30) := NULL;

  PROCEDURE SETUP IS
  BEGIN
    TWOFACTOR_ADMIN.SETUP(PUSER => VUSER, PPASS => VPASS, PGAP => NULL);
  END;

  PROCEDURE DECONFIG(PCODE IN VARCHAR2 DEFAULT NULL) IS
  BEGIN
    TWOFACTOR_ADMIN.DECONFIG(PUSER => VUSER, PCODE => PCODE, PPASS => VPASS, PISADMIN => FALSE);
  END;

  PROCEDURE VALIDATE(PCODE IN VARCHAR2) IS
  BEGIN
    TWOFACTOR_ADMIN.VALIDATE(PUSER => VUSER, PCODE => PCODE, PPASS => VPASS);
  END;

  PROCEDURE AUTHENTICATE(PCODE IN VARCHAR2) IS
  BEGIN
    TWOFACTOR_ADMIN.AUTHENTICATE(PCODE => PCODE, PPASS => VPASS);
  END;

  PROCEDURE REMEMBER(PCODE IN VARCHAR2) IS
  BEGIN
    TWOFACTOR_ADMIN.REMEMBER(PCODE => PCODE, PPASS => VPASS, PINT => NULL);
  END;

  PROCEDURE FORGET IS
  BEGIN
    TWOFACTOR_ADMIN.FORGET(PUSER => VUSER);
  END;

  PROCEDURE SETSECRETPASS(PPASS IN VARCHAR2) IS
  BEGIN
    VPASS := PPASS;
  END;

END TWOFACTOR;
/
