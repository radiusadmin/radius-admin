# Licensing

radius-admin is **source available** under the [Business Source License 1.1](LICENSE) (BSL).
Every feature is in the same public code, and nothing is locked behind a key. The licence
decides who may use it for free and who needs a commercial licence. This page explains the
licence in plain words; if this page and [LICENSE](LICENSE) disagree, LICENSE applies.

## Who may use it for free

| You are | Production use |
|---|---|
| An individual: home network, home lab, learning | Free |
| An organization with **fewer than 50** people (employees and contractors, affiliates included) | Free |
| An organization of any size, during its **first 60 days** of production use (trial) | Free |
| An organization that grew past the limit | Free for **90 days** after it stopped qualifying |
| Anyone testing, developing, evaluating or reading the code (not production) | Free |
| An organization with **50 or more** people, after the trial | **Commercial licence required** |

"Production use" means using radius-admin to run a network that people or devices rely on:
authenticating users, devices or administrators, or assigning VLANs on that network.
A lab or test setup that nothing depends on is not production use.

## Organizations with 50 or more people

An organization whose headcount is 50 or more needs a **commercial licence** for production
use after its 60-day trial. It covers every feature; there is no separate "enterprise edition".

How the headcount is counted:

- Count every **employee and individual independent contractor**, full-time or part-time; each
  person counts as one.
- Count the **whole group**: parent companies, subsidiaries and sister companies under common
  control are one organization.
- Use the **highest number in the previous 12 months**.

**Service providers.** If you run radius-admin for a customer (managed service provider,
hosting provider, consultant), both you and the customer must be under 50 people for the free
use to apply. Otherwise that deployment needs a commercial licence.

**Growing past the limit.** You may keep using it for 90 days after your headcount reaches 50,
so there is time to arrange a licence.

## Exceptions

Organizations with special circumstances can ask for an exception. Exceptions are granted
case by case, in writing.

## Prices

A commercial licence is an annual subscription per organization, priced by headcount (counted
as described above). Every tier includes every feature, unlimited servers and devices, and all
updates published during the subscription.

| Headcount | Price per year |
|---|---|
| 0–49 | Free (no licence needed) |
| 50–249 | USD 1,000 |
| 250–999 | USD 4,000 |
| 1,000–4,999 | USD 10,000 |
| 5,000 or more | On request |

Prices are list prices for a standard licence. Deployments with special requirements, such as
custom terms, several separate deployments or service providers, are quoted individually, and
the final price is the one in the signed agreement.

## How to get a commercial licence

Commercial licences are being set up. Until a licensing address is published, open a private
conversation through the repository (see "Contact" on the project page) and describe your
organization and deployment.
<!-- TODO before the first BSL release: licensing contact address. -->

## Older versions and the future

- Versions **up to and including 0.2.5** stay under the GNU AGPL, version 3 or later, as their
  own LICENSE file says.
- Each later version becomes available under the **GNU AGPL, version 3 or later**, four years
  after it is published (the BSL "Change Date").

## FreeRADIUS

The release bundle also contains the `radius-admin-freeradius` package: FreeRADIUS, a separate
program under its own licence (GNU GPL version 2 or later; parts under the LGPL). The BSL does
not apply to it. radius-admin runs and configures FreeRADIUS; it does not link to it.

## No warranty

radius-admin is provided "as is", without warranty of any kind; see [LICENSE](LICENSE).
