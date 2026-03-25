**Unreleased**

* Fixed an OAuth token generation crash by returning a consistent tuple.
* Test Connectivity now passes with a warning when Microsoft Graph returns a 403 (Forbidden), indicating connectivity is successful but the User.Read.All permission is not granted.
