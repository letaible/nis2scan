"""§30 Abs. 2 Nr. 5 — Schwachstellenmanagement checks for AWS.

Checks ECR image scanning configuration and SSM patch compliance.
"""

from datetime import UTC, datetime
from typing import Any

import structlog

from nis2scan.engine.evidence import compliant_finding
from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity

logger = structlog.get_logger()

BSIG_30_NR = 5
BSIG_30_TEXT = (
    "§30 Abs. 2 Nr. 5 BSIG — Sicherheitsmaßnahmen bei Erwerb, Entwicklung und "
    "Wartung von informationstechnischen Systemen, Komponenten und Prozessen, "
    "einschließlich Management und Offenlegung von Schwachstellen"
)
ISO_CONTROL = "A.8.8 Management of technical vulnerabilities"


class CheckEcrImageScanning(BaseCheck):
    """Check that ECR repositories have scan-on-push enabled."""

    check_id = "AWS-NR5-001"
    title = "ECR Image Scanning"
    description = "Prüft ob ECR-Repositories automatisches Image-Scanning bei Push aktiviert haben."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["ecr:DescribeRepositories"]
    pruefgrenzen = (
        "Prüft nur, ob scanOnPush (Basic Scanning) für ECR-Repositories aktiviert ist. Nicht "
        "geprüft werden Scan-Ergebnisse, deren Behebung, Registries außerhalb von ECR sowie das "
        "registry-weite Enhanced Scanning (Amazon Inspector) — bei aktiviertem Enhanced Scanning "
        "ist scanOnPush ohne Wirkung und dieser Befund gegenstandslos."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            for region in session.regions:
                ecr = session.client("ecr", region=region)

                try:
                    paginator = ecr.get_paginator("describe_repositories")
                    for page in paginator.paginate():
                        for repo in page.get("repositories", []):
                            repo_name = repo.get("repositoryName", "unknown")
                            repo_arn = repo.get("repositoryArn", repo_name)
                            scan_config = repo.get("imageScanningConfiguration", {})
                            scan_on_push = scan_config.get("scanOnPush", False)

                            if scan_on_push:
                                findings.append(
                                    compliant_finding(
                                        self,
                                        title="ECR-Repository mit Image-Scanning",
                                        description=(
                                            f"Das ECR-Repository '{repo_name}' hat automatisches "
                                            f"Image-Scanning bei Push aktiviert."
                                        ),
                                        region=region,
                                        resource_id=repo_arn,
                                        resource_type="AWS::ECR::Repository",
                                        account_id=session.account_id,
                                        current_state={"scan_on_push": True, "repo_name": repo_name},
                                        expected_state="ECR Image Scanning bei Push aktiviert (scanOnPush=true)",
                                        audit_evidence=f"DescribeRepositories: scanOnPush=true for {repo_name}",
                                        iso27001_control=ISO_CONTROL,
                                    )
                                )
                            else:
                                findings.append(
                                    Finding(
                                        check_id=self.check_id,
                                        title="ECR-Repository ohne automatisches Image-Scanning",
                                        description=(
                                            f"Das ECR-Repository '{repo_name}' hat "
                                            f"kein automatisches Image-Scanning bei Push aktiviert. "
                                            f"Ohne Scanning werden Schwachstellen in Container-Images "
                                            f"nicht erkannt. Sofern Enhanced Scanning (Amazon Inspector) "
                                            f"auf Registry-Ebene aktiviert ist, werden Images unabhängig "
                                            f"von dieser Einstellung gescannt; dieser Befund ist dann "
                                            f"gegenstandslos."
                                        ),
                                        bsig_30_nr=BSIG_30_NR,
                                        bsig_30_text=BSIG_30_TEXT,
                                        iso27001_control=ISO_CONTROL,
                                        severity=Severity.HIGH,
                                        provider=CloudProvider.AWS,
                                        region=region,
                                        resource_id=repo_arn,
                                        resource_type="AWS::ECR::Repository",
                                        account_id=session.account_id,
                                        current_state={
                                            "scan_on_push": False,
                                            "repo_name": repo_name,
                                        },
                                        expected_state="ECR Image Scanning bei Push aktiviert (scanOnPush=true)",
                                        remediation=(
                                            "Aktivieren Sie das automatische Image-Scanning: "
                                            "aws ecr put-image-scanning-configuration "
                                            "--repository-name <name> "
                                            "--image-scanning-configuration scanOnPush=true"
                                        ),
                                        remediation_effort="LOW",
                                        audit_evidence=(f"DescribeRepositories: scanOnPush=false for {repo_name}"),
                                    )
                                )
                except Exception as e:
                    errors.append(
                        CheckError(
                            message=f"ECR Check in {region} fehlgeschlagen: {e}",
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"ECR Image Scanning Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckSsmPatchCompliance(BaseCheck):
    """Check that EC2 instances are managed by SSM for patch management."""

    check_id = "AWS-NR5-002"
    title = "SSM Patch Management"
    description = (
        "Prüft ob EC2-Instanzen von AWS Systems Manager verwaltet werden "
        "und damit zentrales Patch-Management möglich ist."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = [
        "ssm:DescribeInstanceInformation",
        "ec2:DescribeInstances",
    ]
    pruefgrenzen = (
        "Prüft nur, ob laufende EC2-Instanzen von AWS Systems Manager verwaltet werden "
        "(SSM-Agent registriert). Nicht geprüft wird, ob Patch-Baselines konfiguriert sind "
        "oder Patches tatsächlich installiert werden (siehe AWS-NR5-003)."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            for region in session.regions:
                ec2 = session.client("ec2", region=region)
                ssm = session.client("ssm", region=region)

                try:
                    # Get all running EC2 instances
                    ec2_paginator = ec2.get_paginator("describe_instances")
                    running_instances = set()
                    for page in ec2_paginator.paginate(
                        Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
                    ):
                        for reservation in page.get("Reservations", []):
                            for instance in reservation.get("Instances", []):
                                running_instances.add(instance["InstanceId"])

                    if not running_instances:
                        continue  # No instances to check

                    # Get SSM-managed instances
                    ssm_paginator = ssm.get_paginator("describe_instance_information")
                    managed_instances = set()
                    for page in ssm_paginator.paginate():
                        for info in page.get("InstanceInformationList", []):
                            managed_instances.add(info["InstanceId"])

                    # Find unmanaged instances
                    unmanaged = running_instances - managed_instances

                    for instance_id in sorted(running_instances & managed_instances):
                        findings.append(
                            compliant_finding(
                                self,
                                title="EC2-Instanz von SSM verwaltet",
                                description=(
                                    f"Die EC2-Instanz '{instance_id}' wird von AWS Systems Manager "
                                    f"verwaltet — zentrales Patch-Management ist möglich."
                                ),
                                region=region,
                                resource_id=instance_id,
                                resource_type="AWS::EC2::Instance",
                                account_id=session.account_id,
                                current_state={"ssm_managed": True, "instance_name": instance_id},
                                expected_state="EC2-Instanz von SSM verwaltet mit SSM Agent aktiv",
                                audit_evidence=f"DescribeInstanceInformation: {instance_id} is SSM-managed",
                                iso27001_control=ISO_CONTROL,
                            )
                        )

                    for instance_id in unmanaged:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="EC2-Instanz nicht von SSM verwaltet",
                                description=(
                                    f"Die EC2-Instanz '{instance_id}' wird nicht "
                                    f"von AWS Systems Manager verwaltet. Ohne SSM ist kein "
                                    f"zentrales Patch-Management möglich."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control=ISO_CONTROL,
                                severity=Severity.HIGH,
                                provider=CloudProvider.AWS,
                                region=region,
                                resource_id=instance_id,
                                resource_type="AWS::EC2::Instance",
                                account_id=session.account_id,
                                current_state={
                                    "ssm_managed": False,
                                    "instance_name": instance_id,
                                },
                                expected_state="EC2-Instanz von SSM verwaltet mit SSM Agent aktiv",
                                remediation=(
                                    "Installieren und aktivieren Sie den SSM Agent auf der Instanz "
                                    "und stellen Sie sicher, dass die Instanz eine IAM-Rolle mit "
                                    "AmazonSSMManagedInstanceCore Policy hat."
                                ),
                                remediation_effort="MEDIUM",
                                audit_evidence=(f"DescribeInstanceInformation: {instance_id} not in SSM managed list"),
                            )
                        )

                except Exception as e:
                    errors.append(
                        CheckError(
                            message=f"SSM Patch Check in {region} fehlgeschlagen: {e}",
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"SSM Patch Compliance Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckLambdaRuntimeDeprecation(BaseCheck):
    """Check that Lambda functions use current, non-deprecated runtimes."""

    check_id = "AWS-NR5-004"
    title = "Lambda Runtime-Versionen"
    description = "Prüft ob Lambda-Funktionen aktuelle, nicht-veraltete Laufzeitumgebungen verwenden."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["lambda:ListFunctions"]
    pruefgrenzen = (
        "Prüft nur Lambda-Runtimes gegen eine im Tool gepflegte Liste veralteter "
        "Versionen. Neue Deprecations nach Mapping-Stand werden erst mit einem "
        "Tool-Update erkannt; Anwendungsabhängigkeiten werden nicht geprüft. "
        "Lambda-Funktionen mit Container-Image-Paketierung (ohne verwaltete Runtime) "
        "werden nicht bewertet."
    )

    # Stand der Liste: Mapping-Release 2026.07. Bei jedem Mapping-Release gegen
    # https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html aktualisieren.
    DEPRECATED_RUNTIMES = {
        "python2.7",
        "python3.6",
        "python3.7",
        "python3.8",
        "python3.9",
        "nodejs10.x",
        "nodejs12.x",
        "nodejs14.x",
        "nodejs16.x",
        "nodejs18.x",
        "nodejs20.x",
        "dotnetcore2.1",
        "dotnetcore3.1",
        "dotnet6",
        "ruby2.5",
        "ruby2.7",
        "ruby3.2",
        "java8",
        "go1.x",
    }

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            for region in session.regions:
                lam = session.client("lambda", region=region)

                try:
                    paginator = lam.get_paginator("list_functions")
                    for page in paginator.paginate():
                        for function in page.get("Functions", []):
                            runtime = function.get("Runtime", "")
                            func_name = function.get("FunctionName", "unknown")
                            func_arn = function.get("FunctionArn", func_name)

                            if runtime and runtime not in self.DEPRECATED_RUNTIMES:
                                findings.append(
                                    compliant_finding(
                                        self,
                                        title="Lambda-Funktion ohne bekannte Runtime-Veraltung",
                                        description=(
                                            f"Die Lambda-Funktion '{func_name}' verwendet die Runtime "
                                            f"'{runtime}', die zum Prüfstand des Tools nicht als veraltet "
                                            f"bekannt ist."
                                        ),
                                        region=region,
                                        resource_id=func_arn,
                                        resource_type="AWS::Lambda::Function",
                                        account_id=session.account_id,
                                        current_state={"runtime": runtime, "function_name": func_name},
                                        expected_state="Aktuelle, unterstützte Lambda Runtime-Version",
                                        audit_evidence=(
                                            f"ListFunctions: {func_name} runtime '{runtime}' not in "
                                            f"deprecated-runtimes list (Stand Mapping 2026.07)"
                                        ),
                                        iso27001_control=ISO_CONTROL,
                                    )
                                )
                            elif runtime in self.DEPRECATED_RUNTIMES:
                                findings.append(
                                    Finding(
                                        check_id=self.check_id,
                                        title=("Lambda-Funktion mit veralteter Runtime"),
                                        description=(
                                            f"Die Lambda-Funktion "
                                            f"'{func_name}'"
                                            f" verwendet die veraltete "
                                            f"Runtime '{runtime}'. "
                                            f"Veraltete Runtimes erhalten"
                                            f" keine Sicherheitsupdates "
                                            f"mehr."
                                        ),
                                        bsig_30_nr=BSIG_30_NR,
                                        bsig_30_text=BSIG_30_TEXT,
                                        iso27001_control=ISO_CONTROL,
                                        severity=Severity.MEDIUM,
                                        provider=CloudProvider.AWS,
                                        region=region,
                                        resource_id=func_arn,
                                        resource_type=("AWS::Lambda::Function"),
                                        account_id=session.account_id,
                                        current_state={
                                            "runtime": runtime,
                                            "function_name": func_name,
                                        },
                                        expected_state=("Aktuelle, unterstützte Lambda Runtime-Version"),
                                        remediation=(
                                            "Aktualisieren Sie die "
                                            "Lambda Runtime: aws lambda "
                                            "update-function-configuration"
                                            " --function-name <name> "
                                            "--runtime <new-runtime>"
                                        ),
                                        remediation_effort="MEDIUM",
                                        audit_evidence=(
                                            f"ListFunctions: {func_name} uses deprecated runtime '{runtime}'"
                                        ),
                                    )
                                )
                except Exception as e:
                    errors.append(
                        CheckError(
                            message=(f"Lambda Runtime Check in {region} fehlgeschlagen: {e}"),
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=(f"Lambda Runtime Deprecation Check fehlgeschlagen: {e}"),
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(
            check_id=self.check_id,
            findings=findings,
            errors=errors,
        )


class CheckAmiAge(BaseCheck):
    """Check that EC2 instances use AMIs younger than 90 days.

    Instances running old AMIs may contain unpatched vulnerabilities and
    outdated software that poses security risks.
    """

    check_id = "AWS-NR5-005"
    title = "AMI-Alter für Produktionsinstanzen"
    description = (
        "Prüft ob EC2-Instanzen AMIs verwenden, die nicht älter als 90 Tage sind, "
        "um sicherzustellen, dass die Betriebsumgebung regelmäßig aktualisiert wird."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["ec2:DescribeInstances", "ec2:DescribeImages"]
    pruefgrenzen = (
        "Bewertet nur das Erstellungsdatum der AMIs laufender Instanzen als Indiz. "
        "Ein altes AMI kann durch Laufzeit-Patching aktuell sein — der tatsächliche "
        "Patchstand der Instanz wird hier nicht geprüft (siehe SSM-Checks). AMIs, die "
        "deregistriert oder nicht zugänglich sind, können nicht bewertet werden; "
        "betroffene Instanzen erscheinen nicht als Prüfobjekt."
    )

    MAX_AMI_AGE_DAYS = 90

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            for region in session.regions:
                ec2 = session.client("ec2", region=region)

                try:
                    paginator = ec2.get_paginator("describe_instances")
                    ami_ids = set()
                    instance_amis: dict[str, list[str]] = {}  # ami_id -> [instance_ids]

                    for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
                        for reservation in page.get("Reservations", []):
                            for instance in reservation.get("Instances", []):
                                ami_id = instance.get("ImageId", "")
                                instance_id = instance.get("InstanceId", "")
                                if ami_id:
                                    ami_ids.add(ami_id)
                                    instance_amis.setdefault(ami_id, []).append(instance_id)

                    if not ami_ids:
                        continue

                    # Describe AMIs
                    try:
                        images = ec2.describe_images(ImageIds=list(ami_ids)).get("Images", [])
                    except Exception as e:
                        # Some AMIs may be deregistered or private — record as error,
                        # never silent (ADR-0016); affected instances stay unevaluated.
                        affected_instances = sum(len(ids) for ids in instance_amis.values())
                        errors.append(
                            CheckError(
                                message=(
                                    f"DescribeImages fehlgeschlagen — AMI-Alter für "
                                    f"{affected_instances} Instanzen in {region} nicht bewertbar: {e}"
                                ),
                                error_type=type(e).__name__,
                            )
                        )
                        images = []

                    now = datetime.now(UTC)
                    image_map = {img["ImageId"]: img for img in images}

                    for ami_id, instance_ids in instance_amis.items():
                        image = image_map.get(ami_id)
                        if not image:
                            continue  # AMI not accessible, skip

                        creation_date_str = image.get("CreationDate", "")
                        if not creation_date_str:
                            continue

                        try:
                            creation_date = datetime.fromisoformat(creation_date_str.replace("Z", "+00:00"))
                            age_days = (now - creation_date).days

                            if age_days <= self.MAX_AMI_AGE_DAYS:
                                for instance_id in instance_ids:
                                    findings.append(
                                        compliant_finding(
                                            self,
                                            title="EC2-Instanz mit aktuellem AMI",
                                            description=(
                                                f"Die EC2-Instanz '{instance_id}' verwendet ein AMI, "
                                                f"das {age_days} Tage alt ist (Maximum: "
                                                f"{self.MAX_AMI_AGE_DAYS} Tage)."
                                            ),
                                            region=region,
                                            resource_id=instance_id,
                                            resource_type="AWS::EC2::Instance",
                                            account_id=session.account_id,
                                            current_state={
                                                "ami_id": ami_id,
                                                "ami_age_days": age_days,
                                                "instance_name": instance_id,
                                            },
                                            expected_state=f"AMI-Alter ≤ {self.MAX_AMI_AGE_DAYS} Tage",
                                            audit_evidence=(
                                                f"DescribeImages: AMI {ami_id} created "
                                                f"{age_days} days ago for {instance_id}"
                                            ),
                                            iso27001_control=ISO_CONTROL,
                                        )
                                    )
                            else:
                                for instance_id in instance_ids:
                                    findings.append(
                                        Finding(
                                            check_id=self.check_id,
                                            title="EC2-Instanz mit veraltetem AMI",
                                            description=(
                                                f"Die EC2-Instanz '{instance_id}' "
                                                f"verwendet ein AMI, das {age_days} Tage alt ist. "
                                                f"AMIs sollten nicht älter als {self.MAX_AMI_AGE_DAYS} "
                                                f"Tage sein."
                                            ),
                                            bsig_30_nr=BSIG_30_NR,
                                            bsig_30_text=BSIG_30_TEXT,
                                            iso27001_control=ISO_CONTROL,
                                            severity=Severity.MEDIUM,
                                            provider=CloudProvider.AWS,
                                            region=region,
                                            resource_id=instance_id,
                                            resource_type="AWS::EC2::Instance",
                                            account_id=session.account_id,
                                            current_state={
                                                "ami_id": ami_id,
                                                "ami_age_days": age_days,
                                                "instance_name": instance_id,
                                            },
                                            expected_state=f"AMI-Alter ≤ {self.MAX_AMI_AGE_DAYS} Tage",
                                            remediation=(
                                                "Aktualisieren Sie das AMI der Instanz: "
                                                "1. Erstellen Sie ein neues AMI mit aktuellen Patches. "
                                                "2. Starten Sie die Instanz mit dem neuen AMI. "
                                                "Nutzen Sie EC2 Image Builder für automatisierte AMI-Erstellung."
                                            ),
                                            remediation_effort="MEDIUM",
                                            audit_evidence=(
                                                f"DescribeImages: AMI {ami_id} created "
                                                f"{age_days} days ago for {instance_id}"
                                            ),
                                        )
                                    )
                        except (ValueError, TypeError) as e:
                            # Record per affected instance instead of a silent skip (ADR-0016)
                            for instance_id in instance_ids:
                                errors.append(
                                    CheckError(
                                        message=(
                                            f"AMI-Erstellungsdatum für {ami_id} (Instanz "
                                            f"{instance_id}) in {region} nicht auswertbar: {e}"
                                        ),
                                        error_type=type(e).__name__,
                                    )
                                )
                            continue

                except Exception as e:
                    errors.append(
                        CheckError(
                            message=f"AMI Age Check in {region} fehlgeschlagen: {e}",
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"AMI Age Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckSsmPatchManagerCompliance(BaseCheck):
    """Check that SSM Patch Manager has custom patch baselines configured."""

    check_id = "AWS-NR5-003"
    title = "SSM Patch Manager Compliance"
    description = "Prüft ob AWS Systems Manager Patch Manager mit benutzerdefinierten Patch-Baselines konfiguriert ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = [
        "ssm:DescribePatchBaselines",
        "ssm:DescribeInstancePatchStates",
        "ssm:DescribeInstanceInformation",
    ]
    pruefgrenzen = (
        "Prüft, ob benutzerdefinierte Patch-Baselines existieren, und stützt sich auf die "
        "von SSM gemeldete Patch-Compliance. Instanzen ohne SSM-Agent oder ohne Patch-Gruppe "
        "erscheinen hier nicht — die SSM-Abdeckung wird gesondert durch AWS-NR5-002 geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            for region in session.regions:
                ssm_client = session.client("ssm", region=region)

                try:
                    # Determine managed instances first — gates the "no custom baseline"
                    # Mangel-Finding below (a region without managed instances has no
                    # Prüfobjekt for patch baselines) and feeds the patch-state check.
                    ssm_paginator = ssm_client.get_paginator("describe_instance_information")
                    managed_ids = []
                    for page in ssm_paginator.paginate():
                        for info in page.get("InstanceInformationList", []):
                            managed_ids.append(info["InstanceId"])

                    # Check for custom patch baselines
                    baselines_resp = ssm_client.describe_patch_baselines(
                        Filters=[
                            {
                                "Key": "OWNER",
                                "Values": ["Self"],
                            }
                        ]
                    )
                    custom_baselines = baselines_resp.get("BaselineIdentities", [])

                    if custom_baselines:
                        findings.append(
                            compliant_finding(
                                self,
                                title="Benutzerdefinierte Patch-Baselines konfiguriert",
                                description=(
                                    f"In der Region '{region}' sind {len(custom_baselines)} "
                                    f"benutzerdefinierte Patch-Baselines konfiguriert."
                                ),
                                region=region,
                                resource_id=f"arn:aws:ssm:{region}:{session.account_id}:patchbaseline/*",
                                resource_type="AWS::SSM::PatchBaseline",
                                account_id=session.account_id,
                                current_state={"custom_baselines": len(custom_baselines)},
                                expected_state="Mindestens eine benutzerdefinierte Patch-Baseline konfiguriert",
                                audit_evidence=(
                                    f"DescribePatchBaselines: {len(custom_baselines)} custom baseline(s) in {region}"
                                ),
                                iso27001_control="A.8.8, A.8.9",
                            )
                        )
                    elif managed_ids:
                        # Only a Mangel when there are managed instances to apply a
                        # baseline to — a region without managed instances has no
                        # Prüfobjekt (B-Nr.5-4).
                        baseline_arn = f"arn:aws:ssm:{region}:{session.account_id}:patchbaseline/*"
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title=("Keine benutzerdefinierten Patch-Baselines konfiguriert"),
                                description=(
                                    "In der Region "
                                    f"'{region}' sind keine "
                                    "benutzerdefinierten "
                                    "Patch-Baselines "
                                    "konfiguriert. Ohne "
                                    "individuelle Baselines "
                                    "werden nur "
                                    "AWS-Standardregeln "
                                    "angewendet. Sofern die "
                                    "AWS-Standard-Baselines "
                                    "bewusst und dokumentiert "
                                    "genutzt werden, ist dies "
                                    "gesondert nachzuweisen."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control=("A.8.8, A.8.9"),
                                severity=Severity.MEDIUM,
                                provider=CloudProvider.AWS,
                                region=region,
                                resource_id=baseline_arn,
                                resource_type=("AWS::SSM::PatchBaseline"),
                                account_id=(session.account_id),
                                current_state={
                                    "custom_baselines": 0,
                                },
                                expected_state=("Mindestens eine benutzerdefinierte Patch-Baseline konfiguriert"),
                                remediation=(
                                    "Erstellen Sie eine "
                                    "benutzerdefinierte "
                                    "Patch-Baseline: aws ssm"
                                    " create-patch-baseline "
                                    "--name <name> "
                                    "--operating-system "
                                    "<os> --approval-rules "
                                    "<rules>"
                                ),
                                remediation_effort=("MEDIUM"),
                                audit_evidence=(f"DescribePatchBaselines: no custom baselines in {region}"),
                            )
                        )

                    patch_states: list[dict[str, Any]] = []
                    if managed_ids:
                        patch_states_resp = ssm_client.describe_instance_patch_states(InstanceIds=managed_ids)
                        patch_states = patch_states_resp.get("InstancePatchStates", [])

                    for state in patch_states:
                        instance_id = state.get("InstanceId", "unknown")
                        missing = state.get("MissingCount", 0)
                        failed = state.get("FailedCount", 0)

                        if missing == 0 and failed == 0:
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="Instanz vollständig gepatcht",
                                    description=(
                                        f"Die Instanz '{instance_id}' hat keine fehlenden oder "
                                        f"fehlgeschlagenen Patches."
                                    ),
                                    region=region,
                                    resource_id=instance_id,
                                    resource_type="AWS::SSM::ManagedInstance",
                                    account_id=session.account_id,
                                    current_state={
                                        "missing_count": 0,
                                        "failed_count": 0,
                                        "instance_name": instance_id,
                                    },
                                    expected_state=(
                                        "Alle Patches erfolgreich installiert (MissingCount=0, FailedCount=0)"
                                    ),
                                    audit_evidence=(f"DescribeInstancePatchStates: {instance_id} missing=0, failed=0"),
                                    iso27001_control="A.8.8, A.8.9",
                                )
                            )
                        else:
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title=("Instanz mit fehlenden oder fehlgeschlagenen Patches"),
                                    description=(
                                        "Die Instanz "
                                        f"'{instance_id}'"
                                        f" hat {missing} "
                                        "fehlende und "
                                        f"{failed} "
                                        "fehlgeschlagene "
                                        "Patches."
                                    ),
                                    bsig_30_nr=(BSIG_30_NR),
                                    bsig_30_text=(BSIG_30_TEXT),
                                    iso27001_control=("A.8.8, A.8.9"),
                                    severity=(Severity.HIGH),
                                    provider=(CloudProvider.AWS),
                                    region=region,
                                    resource_id=(instance_id),
                                    resource_type=("AWS::SSM::ManagedInstance"),
                                    account_id=(session.account_id),
                                    current_state={
                                        "missing_count": missing,
                                        "failed_count": failed,
                                        "instance_name": instance_id,
                                    },
                                    expected_state=(
                                        "Alle Patches erfolgreich installiert (MissingCount=0, FailedCount=0)"
                                    ),
                                    remediation=(
                                        "Führen Sie "
                                        "ausstehende "
                                        "Patches aus: "
                                        "aws ssm "
                                        "send-command "
                                        "--document-name "
                                        "AWS-RunPatch"
                                        "Baseline "
                                        "--instance-ids "
                                        "<id>"
                                    ),
                                    remediation_effort=("MEDIUM"),
                                    audit_evidence=(
                                        f"DescribeInstancePatchStates: {instance_id} missing={missing}, failed={failed}"
                                    ),
                                )
                            )

                except Exception as e:
                    errors.append(
                        CheckError(
                            message=(f"SSM Patch Manager Check in {region} fehlgeschlagen: {e}"),
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=(f"SSM Patch Manager Compliance Check fehlgeschlagen: {e}"),
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(
            check_id=self.check_id,
            findings=findings,
            errors=errors,
        )
