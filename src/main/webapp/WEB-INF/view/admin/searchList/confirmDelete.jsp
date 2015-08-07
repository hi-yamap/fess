<%@page pageEncoding="UTF-8" contentType="text/html; charset=UTF-8"%><!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Fess | <bean:message key="labels.search_list_configuration" /></title>
<jsp:include page="/WEB-INF/view/common/admin2/head.jsp"></jsp:include>
</head>
<body class="skin-blue sidebar-mini">
	<div class="wrapper">
		<jsp:include page="/WEB-INF/view/common/admin2/header.jsp"></jsp:include>
		<jsp:include page="/WEB-INF/view/common/admin2/sidebar.jsp">
			<jsp:param name="menuCategoryType" value="crawl" />
			<jsp:param name="menuType" value="searchList" />
		</jsp:include>

		<div class="content-wrapper">

			<%-- Content Header --%>
			<section class="content-header">
				<h1>
					<bean:message key="labels.search_list_title_confirm_delete" />
				</h1>
				<ol class="breadcrumb">
					<li><s:link href="index">
							<bean:message key="labels.search_list_title_confirm_delete" />
						</s:link></li>
				</ol>
			</section>

			<section class="content">

				<%-- Form --%>
				<s:form>
					<div class="row">
						<div class="col-md-12">
							<div class="box">
								<%-- Box Header --%>
								<div class="box-header with-border">
									
								</div>
								<%-- Box Body --%>
								<div class="box-body">
									<s:form>
										<html:hidden property="query" />
										<div>
											<table class="bordered-table zebra-striped">
												<tbody>
													<tr>
														<th style="width: 100px;"><bean:message
																key="labels.search_list_url" /></th>
														<td style="width: 400px;">${f:h(url)}<html:hidden
																property="docId" /></td>
													</tr>
												</tbody>
												<tfoot>
													<tr>
														<td colspan="2"><input type="submit" class="btn small" name="delete"
															value="<bean:message key="labels.crud_button_delete"/>" /> <input
															type="submit" class="btn small" name="search"
															value="<bean:message key="labels.crud_button_back"/>" /></td>
													</tr>
												</tfoot>
											</table>
										</div>
									</s:form>
								</div>
								<%-- Box Footer --%>
								<div class="box-footer">
									
								</div>
							</div>
						</div>
					</div>
				</s:form>

			</section>
		</div>

		<jsp:include page="/WEB-INF/view/common/admin2/footer.jsp"></jsp:include>
	</div>
	<jsp:include page="/WEB-INF/view/common/admin2/foot.jsp"></jsp:include>
</body>
</html>

